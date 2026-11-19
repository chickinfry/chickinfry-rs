//! Generic ORM execution core. Generators emit typed row, insert, update, and
//! primary-key structs plus per-table repositories that delegate to this
//! module; identifiers are always quoted and data values always bound as
//! parameters.

use crate::database::{DatabasePort, TransactionPort};
use crate::server::OperationError;
use chrono::{DateTime, Datelike, Utc};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Id,
    Text,
    Integer,
    Date,
    Timestamp,
}

impl Kind {
    pub fn from_name(name: &str) -> Kind {
        match name {
            "id" => Kind::Id,
            "integer" => Kind::Integer,
            "date" => Kind::Date,
            "timestamp" => Kind::Timestamp,
            _ => Kind::Text,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Column {
    pub database_name: &'static str,
    pub kind: Kind,
    pub nullable: bool,
    /// Optional columns may be omitted on insert (default or nullable).
    pub optional: bool,
    pub unique: bool,
    pub references: &'static str,
}

impl Column {
    pub const fn new(
        database_name: &'static str,
        kind: Kind,
        nullable: bool,
        optional: bool,
        unique: bool,
        references: &'static str,
    ) -> Column {
        Column {
            database_name,
            kind,
            nullable,
            optional,
            unique,
            references,
        }
    }
}

pub struct TableDefinition {
    pub name: &'static str,
    pub primary_key: &'static [&'static str],
    pub columns: &'static [Column],
}

impl TableDefinition {
    pub const fn new(
        name: &'static str,
        primary_key: &'static [&'static str],
        columns: &'static [Column],
    ) -> TableDefinition {
        TableDefinition {
            name,
            primary_key,
            columns,
        }
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns
            .iter()
            .find(|column| column.database_name == name)
    }

    fn select_list(&self) -> Result<String, OperationError> {
        let names = self
            .columns
            .iter()
            .map(|column| quote(column.database_name))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names.join(", "))
    }
}

#[derive(Clone, Copy)]
pub enum Operator {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

impl Operator {
    fn sql(self) -> &'static str {
        match self {
            Operator::Equal => "=",
            Operator::NotEqual => "<>",
            Operator::Less => "<",
            Operator::LessEqual => "<=",
            Operator::Greater => ">",
            Operator::GreaterEqual => ">=",
        }
    }
}

/// Typed condition tree. Column kinds are validated against values when the
/// filter compiles.
#[derive(Clone)]
pub enum Filter {
    Comparison {
        column: Column,
        operator: Operator,
        value: serde_json::Value,
    },
    In {
        column: Column,
        values: Vec<serde_json::Value>,
    },
    Null {
        column: Column,
        negated: bool,
    },
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
}

impl Filter {
    pub fn eq(column: Column, value: serde_json::Value) -> Filter {
        Filter::Comparison {
            column,
            operator: Operator::Equal,
            value,
        }
    }
    pub fn ne(column: Column, value: serde_json::Value) -> Filter {
        Filter::Comparison {
            column,
            operator: Operator::NotEqual,
            value,
        }
    }
    pub fn lt(column: Column, value: serde_json::Value) -> Filter {
        Filter::Comparison {
            column,
            operator: Operator::Less,
            value,
        }
    }
    pub fn lte(column: Column, value: serde_json::Value) -> Filter {
        Filter::Comparison {
            column,
            operator: Operator::LessEqual,
            value,
        }
    }
    pub fn gt(column: Column, value: serde_json::Value) -> Filter {
        Filter::Comparison {
            column,
            operator: Operator::Greater,
            value,
        }
    }
    pub fn gte(column: Column, value: serde_json::Value) -> Filter {
        Filter::Comparison {
            column,
            operator: Operator::GreaterEqual,
            value,
        }
    }
    pub fn is_null(column: Column) -> Filter {
        Filter::Null {
            column,
            negated: false,
        }
    }
    pub fn is_not_null(column: Column) -> Filter {
        Filter::Null {
            column,
            negated: true,
        }
    }
    pub fn is_in(column: Column, values: Vec<serde_json::Value>) -> Filter {
        Filter::In { column, values }
    }
    pub fn and(filters: Vec<Filter>) -> Filter {
        Filter::And(filters)
    }
    pub fn or(filters: Vec<Filter>) -> Filter {
        Filter::Or(filters)
    }
    #[expect(
        clippy::should_implement_trait,
        reason = "The shared ORM contract uses this associated constructor."
    )]
    pub fn not(filter: Filter) -> Filter {
        Filter::Not(Box::new(filter))
    }
}

#[derive(Clone, Copy)]
pub enum Direction {
    Ascending,
    Descending,
}

#[derive(Clone, Copy)]
pub struct Order {
    pub column: Column,
    pub direction: Direction,
}

#[derive(Default)]
pub struct FindMany {
    pub r#where: Option<Filter>,
    pub order_by: Vec<Order>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Connection abstraction shared by pooled and transaction repositories.
#[derive(Clone, Copy)]
pub enum Connection {
    Pooled(DatabasePort),
    Transactional(TransactionPort),
}

impl Connection {
    async fn query(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, OperationError> {
        match self {
            Connection::Pooled(port) => port.query(sql, params).await,
            Connection::Transactional(port) => port.query(sql, params).await,
        }
    }
}

pub struct Repository {
    table: &'static TableDefinition,
    connection: Connection,
}

impl Repository {
    pub fn new(table: &'static TableDefinition, port: DatabasePort) -> Repository {
        Repository {
            table,
            connection: Connection::Pooled(port),
        }
    }

    pub fn transactional(table: &'static TableDefinition, connection: Connection) -> Repository {
        Repository { table, connection }
    }

    #[allow(dead_code)]
    pub(crate) fn table(&self) -> &'static TableDefinition {
        self.table
    }

    pub async fn insert<R: serde::de::DeserializeOwned>(
        &self,
        insert: &serde_json::Value,
    ) -> Result<R, OperationError> {
        self.insert_row(insert, false).await
    }

    pub async fn upsert<R: serde::de::DeserializeOwned>(
        &self,
        insert: &serde_json::Value,
    ) -> Result<R, OperationError> {
        self.insert_row(insert, true).await
    }

    async fn insert_row<R: serde::de::DeserializeOwned>(
        &self,
        insert: &serde_json::Value,
        upsert: bool,
    ) -> Result<R, OperationError> {
        let entries = insert.as_object().ok_or_else(OperationError::internal)?;
        let mut names = Vec::new();
        let mut params = Vec::new();
        for (name, value) in entries {
            let column = self
                .table
                .column(name)
                .ok_or_else(OperationError::internal)?;
            encode_value(column, value, &mut params)?;
            names.push(name.as_str());
        }
        let quoted: Vec<String> = names
            .iter()
            .map(|name| quote(name))
            .collect::<Result<_, _>>()?;
        let placeholders: Vec<String> = (1..=names.len()).map(placeholder).collect();
        let mut sql = if names.is_empty() {
            format!("insert into {} default values", quote(self.table.name)?)
        } else {
            format!(
                "insert into {} ({}) values ({})",
                quote(self.table.name)?,
                quoted.join(", "),
                placeholders.join(", ")
            )
        };
        if upsert {
            if self
                .table
                .primary_key
                .iter()
                .any(|name| !entries.contains_key(*name))
            {
                return Err(OperationError::internal());
            }
            let assignments = names
                .iter()
                .filter(|name| !self.table.primary_key.contains(name))
                .map(|name| quote(name).map(|name| format!("{name} = excluded.{name}")))
                .collect::<Result<Vec<_>, _>>()?;
            if assignments.is_empty() {
                return Err(OperationError::internal());
            }
            let primary = self
                .table
                .primary_key
                .iter()
                .map(|name| quote(name))
                .collect::<Result<Vec<_>, _>>()?;
            sql.push_str(&format!(
                " on conflict ({}) do update set {}",
                primary.join(", "),
                assignments.join(", ")
            ));
        }
        sql.push_str(&format!(" returning {}", self.table.select_list()?));
        self.one(&sql, &params).await
    }

    pub async fn find_by_id<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
    ) -> Result<Option<R>, OperationError> {
        let (where_clause, params) = self.primary_key_filter(key, 0)?;
        let sql = format!(
            "select {} from {} where {} limit 1",
            self.table.select_list()?,
            quote(self.table.name)?,
            where_clause
        );
        Ok(self.many(&sql, &params).await?.into_iter().next())
    }

    pub async fn find_many<R: serde::de::DeserializeOwned>(
        &self,
        options: FindMany,
    ) -> Result<Vec<R>, OperationError> {
        let mut params = Vec::new();
        let mut sql = format!(
            "select {} from {}",
            self.table.select_list()?,
            quote(self.table.name)?
        );
        if let Some(filter) = options.r#where {
            let where_clause = compile_filter(&filter, &mut params)?;
            sql.push_str(" where ");
            sql.push_str(&where_clause);
        }
        if !options.order_by.is_empty() {
            let terms = options
                .order_by
                .iter()
                .map(|order| {
                    let name = order.column.database_name;
                    if self.table.column(name).is_none() {
                        return Err(OperationError::internal());
                    }
                    let direction = match order.direction {
                        Direction::Ascending => "asc",
                        Direction::Descending => "desc",
                    };
                    Ok(format!("{} {}", quote(name)?, direction))
                })
                .collect::<Result<Vec<_>, OperationError>>()?;
            sql.push_str(" order by ");
            sql.push_str(&terms.join(", "));
        }
        if let Some(limit) = options.limit {
            params.push(serde_json::json!(limit));
            sql.push_str(&format!(" limit {}", placeholder(params.len())));
        }
        if let Some(offset) = options.offset {
            params.push(serde_json::json!(offset));
            sql.push_str(&format!(" offset {}", placeholder(params.len())));
        }
        self.many(&sql, &params).await
    }

    /// Updates the row behind the primary key. Primary-key columns are
    /// rejected in the patch, so updates can never move a row identity.
    pub async fn update<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
        patch: &serde_json::Value,
    ) -> Result<R, OperationError> {
        self.update_optional(key, None, patch)
            .await?
            .ok_or_else(|| OperationError::from_code("not_found", 404))
    }

    pub async fn update_if<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
        filter: &Filter,
        patch: &serde_json::Value,
    ) -> Result<Option<R>, OperationError> {
        self.update_optional(key, Some(filter), patch).await
    }

    async fn update_optional<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
        filter: Option<&Filter>,
        patch: &serde_json::Value,
    ) -> Result<Option<R>, OperationError> {
        self.update_matching(key, filter, &serde_json::json!({}), patch)
            .await
    }

    pub async fn increment<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
        columns: &serde_json::Value,
    ) -> Result<R, OperationError> {
        if columns.as_object().is_none_or(|columns| columns.is_empty()) {
            return Err(OperationError::internal());
        }
        self.update_matching(key, None, columns, &serde_json::json!({}))
            .await?
            .ok_or_else(|| OperationError::from_code("not_found", 404))
    }

    pub async fn increment_if<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
        condition: &Filter,
        columns: &serde_json::Value,
        patch: &serde_json::Value,
    ) -> Result<Option<R>, OperationError> {
        if columns.as_object().is_none_or(|columns| columns.is_empty())
            || patch.as_object().is_none_or(|patch| patch.is_empty())
        {
            return Err(OperationError::internal());
        }
        self.update_matching(key, Some(condition), columns, patch)
            .await
    }

    async fn update_matching<R: serde::de::DeserializeOwned>(
        &self,
        key: &serde_json::Value,
        filter: Option<&Filter>,
        columns: &serde_json::Value,
        patch: &serde_json::Value,
    ) -> Result<Option<R>, OperationError> {
        let entries = patch.as_object().ok_or_else(OperationError::internal)?;
        let increments = columns.as_object().ok_or_else(OperationError::internal)?;
        let primary_keys: std::collections::BTreeSet<&str> =
            self.table.primary_key.iter().copied().collect();
        let mut assignments = Vec::new();
        let mut params = Vec::new();
        for (name, amount) in increments {
            let column = self
                .table
                .column(name)
                .ok_or_else(OperationError::internal)?;
            if primary_keys.contains(name.as_str())
                || column.kind != Kind::Integer
                || amount.as_i64().is_none_or(|amount| amount == 0)
                || entries.contains_key(name)
            {
                return Err(OperationError::internal());
            }
            encode_value(column, amount, &mut params)?;
            let name = quote(name)?;
            assignments.push(format!("{name} = {name} + {}", placeholder(params.len())));
        }
        for (name, value) in entries {
            if primary_keys.contains(name.as_str()) {
                return Err(OperationError::internal());
            }
            let column = self
                .table
                .column(name)
                .ok_or_else(OperationError::internal)?;
            encode_value(column, value, &mut params)?;
            assignments.push(format!("{} = {}", quote(name)?, placeholder(params.len())));
        }
        if assignments.is_empty() {
            return Err(OperationError::internal());
        }
        let (mut where_clause, mut key_params) = self.primary_key_filter(key, params.len())?;
        params.append(&mut key_params);
        if let Some(filter) = filter {
            where_clause.push_str(" and (");
            where_clause.push_str(&compile_filter(filter, &mut params)?);
            where_clause.push(')');
        }
        let sql = format!(
            "update {} set {} where {} returning {}",
            quote(self.table.name)?,
            assignments.join(", "),
            where_clause,
            self.table.select_list()?
        );
        Ok(self.many(&sql, &params).await?.into_iter().next())
    }

    pub async fn delete(&self, key: &serde_json::Value) -> Result<bool, OperationError> {
        let (where_clause, params) = self.primary_key_filter(key, 0)?;
        let sql = format!(
            "delete from {} where {} returning {}",
            quote(self.table.name)?,
            where_clause,
            self.table.select_list()?
        );
        let rows = self.connection.query(&sql, &params).await?;
        Ok(!rows.is_empty())
    }

    fn primary_key_filter(
        &self,
        key: &serde_json::Value,
        offset: usize,
    ) -> Result<(String, Vec<serde_json::Value>), OperationError> {
        let entries = key.as_object().ok_or_else(OperationError::internal)?;
        if entries.len() != self.table.primary_key.len() {
            return Err(OperationError::internal());
        }
        let mut params = Vec::new();
        let mut terms = Vec::new();
        for name in self.table.primary_key {
            let column = self
                .table
                .column(name)
                .ok_or_else(OperationError::internal)?;
            let value = entries.get(*name).ok_or_else(OperationError::internal)?;
            encode_value(column, value, &mut params)?;
            terms.push(format!(
                "{} = {}",
                quote(name)?,
                placeholder(offset + params.len())
            ));
        }
        Ok((terms.join(" and "), params))
    }

    async fn one<R: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<R, OperationError> {
        let rows = self.connection.query(sql, params).await?;
        rows.into_iter()
            .next()
            .map(|row| self.decode_row(row))
            .transpose()
            .and_then(|value| value.ok_or_else(OperationError::internal))
    }

    async fn many<R: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<R>, OperationError> {
        let rows = self.connection.query(sql, params).await?;
        rows.into_iter().map(|row| self.decode_row(row)).collect()
    }

    fn decode_row<R: serde::de::DeserializeOwned>(
        &self,
        mut row: serde_json::Map<String, serde_json::Value>,
    ) -> Result<R, OperationError> {
        for column in self.table.columns {
            let value = row
                .get_mut(column.database_name)
                .ok_or_else(OperationError::internal)?;
            if column.kind == Kind::Timestamp && !value.is_null() {
                let text = value.as_str().ok_or_else(OperationError::internal)?;
                let timestamp = parse_timestamp(text, true)?;
                let utc = timestamp.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                let (whole, fraction) = utc.split_once('.').ok_or_else(OperationError::internal)?;
                let micros = &fraction[..6];
                let digits = micros.trim_end_matches('0').len().max(3);
                *value = serde_json::Value::String(format!("{whole}.{}Z", &micros[..digits]));
            }
            encode_value(column, value, &mut Vec::new())?;
        }
        serde_json::from_value(serde_json::Value::Object(row))
            .map_err(|_| OperationError::internal())
    }
}

/// Builds one PostgreSQL numbered parameter placeholder.
pub fn placeholder(index: usize) -> String {
    let mut out = String::from("$");
    out.push_str(&index.to_string());
    out
}

fn compile_filter(
    filter: &Filter,
    params: &mut Vec<serde_json::Value>,
) -> Result<String, OperationError> {
    match filter {
        Filter::Comparison {
            column,
            operator,
            value,
        } => {
            filter_value(value).map_err(|_| OperationError::internal())?;
            encode_value(column, value, params)?;
            Ok(format!(
                "{} {} {}",
                quote(column.database_name)?,
                operator.sql(),
                placeholder(params.len())
            ))
        }
        Filter::In { column, values } => {
            if values.is_empty() {
                return Ok("false".to_string());
            }
            let mut placeholders = Vec::with_capacity(values.len());
            for value in values {
                filter_value(value).map_err(|_| OperationError::internal())?;
                encode_value(column, value, params)?;
                placeholders.push(placeholder(params.len()));
            }
            Ok(format!(
                "{} in ({})",
                quote(column.database_name)?,
                placeholders.join(", ")
            ))
        }
        Filter::Null { column, negated } => {
            let base = format!("{} is null", quote(column.database_name)?);
            Ok(if *negated {
                format!("not ({})", base)
            } else {
                base
            })
        }
        Filter::And(filters) => join_filters(filters, " and ", params),
        Filter::Or(filters) if filters.is_empty() => Ok("false".into()),
        Filter::Or(filters) => join_filters(filters, " or ", params),
        Filter::Not(inner) => {
            let compiled = compile_filter(inner, params)?;
            Ok(format!("not ({})", compiled))
        }
    }
}

const NULL_FILTER_ERROR: &str = "Filter values cannot be null; use is_null or is_not_null.";

fn filter_value(value: &serde_json::Value) -> Result<(), &'static str> {
    if value.is_null() {
        Err(NULL_FILTER_ERROR)
    } else {
        Ok(())
    }
}

fn join_filters(
    filters: &[Filter],
    separator: &str,
    params: &mut Vec<serde_json::Value>,
) -> Result<String, OperationError> {
    if filters.is_empty() {
        return Ok("true".to_string());
    }
    let compiled = filters
        .iter()
        .map(|filter| compile_filter(filter, params))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("({})", compiled.join(separator)))
}

fn parse_timestamp(text: &str, postgres: bool) -> Result<DateTime<Utc>, OperationError> {
    if let Some((_, decimal)) = text.split_once('.')
        && decimal.bytes().take_while(u8::is_ascii_digit).count() > 6
    {
        return Err(OperationError::internal());
    }
    let parsed = DateTime::parse_from_rfc3339(text).or_else(|error| {
        if postgres {
            DateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f%#z")
        } else {
            Err(error)
        }
    });
    let timestamp = parsed.map_err(|_| OperationError::internal())?;
    let utc = timestamp.to_utc();
    if !(1..=9999).contains(&timestamp.year()) || !(1..=9999).contains(&utc.year()) {
        return Err(OperationError::internal());
    }
    Ok(utc)
}

/// Encodes one logical value with its declared column kind. PostgreSQL receives
/// dates and timestamps as strings so timezone moves and millisecond
/// truncation cannot lose microseconds.
fn encode_value(
    column: &Column,
    value: &serde_json::Value,
    params: &mut Vec<serde_json::Value>,
) -> Result<(), OperationError> {
    if value.is_null() {
        if !column.nullable {
            return Err(OperationError::internal());
        }
        params.push(serde_json::Value::Null);
        return Ok(());
    }
    match column.kind {
        Kind::Integer => match value.as_i64() {
            Some(number) if number >= i64::from(i32::MIN) && number <= i64::from(i32::MAX) => {
                params.push(serde_json::json!(number as i32));
            }
            _ => return Err(OperationError::internal()),
        },
        Kind::Id | Kind::Text | Kind::Date | Kind::Timestamp => {
            let text = value.as_str().ok_or_else(OperationError::internal)?;
            if text.contains('\0') {
                return Err(OperationError::internal());
            }
            match column.kind {
                Kind::Id
                    if text.len() != 36
                        || !text.bytes().enumerate().all(|(index, byte)| {
                            if [8, 13, 18, 23].contains(&index) {
                                byte == b'-'
                            } else {
                                byte.is_ascii_hexdigit()
                            }
                        }) =>
                {
                    return Err(OperationError::internal());
                }
                Kind::Date => {
                    let date = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
                        .map_err(|_| OperationError::internal())?;
                    if date.format("%Y-%m-%d").to_string() != text {
                        return Err(OperationError::internal());
                    }
                }
                Kind::Timestamp => {
                    parse_timestamp(text, false)?;
                }
                _ => {}
            }
            params.push(value.clone());
        }
    }
    Ok(())
}

/// Quotes one SQL identifier after validating the generator-declared shape.
pub fn quote(name: &str) -> Result<String, OperationError> {
    let head = name
        .chars()
        .next()
        .map(|character| character.is_ascii_lowercase());
    let valid = head.unwrap_or(false)
        && name.len() <= 63
        && name.chars().enumerate().all(|(index, character)| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || (character == '_' && index > 0)
        });
    if valid {
        Ok(format!("\"{}\"", name.replace('"', "\"\"")))
    } else {
        Err(OperationError::internal())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::host::testing;
    use serde_json::{Value, json};

    static TABLE: TableDefinition = TableDefinition::new(
        "records",
        &["id"],
        &[
            Column::new("id", Kind::Integer, false, false, false, ""),
            Column::new("count", Kind::Integer, true, true, false, ""),
            Column::new("name", Kind::Text, false, false, false, ""),
        ],
    );

    #[test]
    fn orm_preserves_microseconds_without_extra_fraction_digits() {
        static DATES: TableDefinition = TableDefinition::new(
            "dates",
            &["id"],
            &[Column::new(
                "seen_at",
                Kind::Timestamp,
                false,
                false,
                false,
                "",
            )],
        );
        let repository = Repository::new(&DATES, DatabasePort::new(1));
        let row = json!({"seen_at": "2026-01-02 12:04:05.123450+09"});
        let decoded: Value = repository
            .decode_row(row.as_object().unwrap().clone())
            .ok()
            .unwrap();
        assert_eq!(decoded["seen_at"], "2026-01-02T03:04:05.12345Z");
        for invalid in ["2026-01-02T03:04:05.1234560Z", "0000-01-01T00:00:00Z"] {
            let mut params = Vec::new();
            assert!(encode_value(&DATES.columns[0], &json!(invalid), &mut params).is_err());
            assert!(params.is_empty());
        }
    }

    #[test]
    fn null_comparisons_require_null_predicates() {
        let column = TABLE.columns[1];
        for filter in [
            Filter::eq(column, Value::Null),
            Filter::ne(column, Value::Null),
            Filter::is_in(column, vec![json!(1), Value::Null]),
        ] {
            let error = compile_filter(&filter, &mut Vec::new()).expect_err("null comparison");
            assert_eq!(error.code, "operation_failed");
            assert_eq!(error.status, 500);
        }
        assert!(compile_filter(&Filter::is_null(column), &mut Vec::new()).is_ok());
    }

    #[test]
    fn missing_update_returns_not_found() {
        let repository = Repository::new(&TABLE, DatabasePort::new(1));
        let error = testing::run(
            |_| json!({"rows": []}),
            repository.update::<Value>(&json!({"id": 1}), &json!({"name": "missing"})),
        )
        .expect_err("missing update");
        assert_eq!(error.code, "not_found");
        assert_eq!(error.status, 404);
        let error = testing::run(
            |_| json!({"rows": []}),
            repository.increment::<Value>(&json!({"id": 1}), &json!({"count": 1})),
        )
        .expect_err("missing increment");
        assert_eq!(error.code, "not_found");
        assert_eq!(error.status, 404);
        let row = testing::run(
            |_| json!({"rows": []}),
            repository.increment_if::<Value>(
                &json!({"id": 1}),
                &Filter::eq(TABLE.columns[1], json!(2)),
                &json!({"count": 1}),
                &json!({"name": "changed"}),
            ),
        );
        assert!(matches!(row, Ok(None)));
    }

    #[test]
    fn upsert_and_conditional_increment_bind_values_atomically() {
        let repository = Repository::new(&TABLE, DatabasePort::new(1));
        let row = json!({"id": 1, "count": 3, "name": "changed"});
        for (upsert, expected_sql, expected_params) in [
            (
                true,
                "insert into \"records\" (\"count\", \"id\", \"name\") values ($1, $2, $3) on conflict (\"id\") do update set \"count\" = excluded.\"count\", \"name\" = excluded.\"name\" returning \"id\", \"count\", \"name\"",
                json!([3, 1, "changed"]),
            ),
            (
                false,
                "update \"records\" set \"count\" = \"count\" + $1, \"name\" = $2 where \"id\" = $3 and (\"count\" = $4) returning \"id\", \"count\", \"name\"",
                json!([1, "changed", 1, 2]),
            ),
        ] {
            let output = row.clone();
            let result = testing::run(
                move |request| {
                    assert_eq!(request["sql"], expected_sql);
                    assert_eq!(request["params"], expected_params);
                    json!({"rows": [output]})
                },
                async {
                    if upsert {
                        repository.upsert::<Value>(&row).await.map(Some)
                    } else {
                        repository
                            .increment_if::<Value>(
                                &json!({"id": 1}),
                                &Filter::eq(TABLE.columns[1], json!(2)),
                                &json!({"count": 1}),
                                &json!({"name": "changed"}),
                            )
                            .await
                    }
                },
            );
            assert!(matches!(result, Ok(Some(value)) if value == row));
        }
        for (amounts, patch) in [
            (json!({"count": 0}), json!({"name": "changed"})),
            (json!({"count": 2147483648_i64}), json!({"name": "changed"})),
            (json!({"name": 1}), json!({"count": 1})),
            (json!({"id": 1}), json!({"name": "changed"})),
            (json!({"count": 1}), json!({"count": 2})),
            (json!({"count": 1}), json!({})),
        ] {
            let result = testing::run(
                |_| panic!("invalid increment reached the database"),
                repository.increment_if::<Value>(
                    &json!({"id": 1}),
                    &Filter::is_null(TABLE.columns[1]),
                    &amounts,
                    &patch,
                ),
            );
            assert!(result.is_err());
        }
        for row in [json!({"id": 1}), json!({"name": "missing key"})] {
            assert!(
                testing::run(
                    |_| panic!("invalid upsert reached the database"),
                    repository.upsert::<Value>(&row)
                )
                .is_err()
            );
        }
    }
}
