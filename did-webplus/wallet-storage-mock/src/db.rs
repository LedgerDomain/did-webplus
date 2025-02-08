use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum OnConflict {
    Abort,
    Ignore,
    Replace,
}

#[derive(Debug)]
pub struct TableError(Cow<'static, str>);

impl std::fmt::Display for TableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&'static str> for TableError {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for TableError {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl From<TableError> for did_webplus_doc_store::Error {
    fn from(table_error: TableError) -> Self {
        did_webplus_doc_store::Error::StorageError(table_error.0)
    }
}

impl From<TableError> for did_webplus_wallet_store::Error {
    fn from(table_error: TableError) -> Self {
        did_webplus_wallet_store::Error::StorageError(table_error.0)
    }
}

pub type TableResult<T> = std::result::Result<T, TableError>;

/// Trait which defines a "sigil", which should be an empty struct that represents the name of something.
pub trait SigilT: Clone + Copy + std::fmt::Debug + Eq + std::hash::Hash {}

// pub type RowId = usize;
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RowId<Sigil: SigilT> {
    row_id: usize,
    phantom: std::marker::PhantomData<Sigil>,
}

impl<Sigil: SigilT> RowId<Sigil> {
    pub fn increment(&mut self) {
        self.row_id += 1;
    }
}

impl<Sigil: SigilT> std::ops::Deref for RowId<Sigil> {
    type Target = usize;
    fn deref(&self) -> &Self::Target {
        &self.row_id
    }
}

impl<Sigil: SigilT> From<usize> for RowId<Sigil> {
    fn from(row_id: usize) -> Self {
        Self {
            row_id,
            phantom: Default::default(),
        }
    }
}

pub trait PrimaryKeyT: Clone + Eq + std::hash::Hash {}

impl<T: Clone + Eq + std::hash::Hash> PrimaryKeyT for T {}

pub trait RowT<PrimaryKey: PrimaryKeyT> {
    fn primary_key(&self) -> &PrimaryKey;
}

/// Sigil should be an empty struct that simply represents the name of the table and is used to
/// distinguish RowId-s of different tables.
#[derive(Clone, Debug)]
pub struct Table<Sigil: SigilT, Row: Clone> {
    /// Stores the row_id to assign to the next Row to be inserted.
    next_rowid: RowId<Sigil>,
    /// Maps assigned row_id to Row.
    row_m: HashMap<RowId<Sigil>, Row>,
}

impl<Sigil: SigilT, Row: Clone> Table<Sigil, Row> {
    pub fn new() -> Self {
        Self {
            next_rowid: RowId::from(0),
            row_m: HashMap::new(),
        }
    }
    /// Returns the row_id if the inserted Row.
    pub fn insert(&mut self, row: Row) -> RowId<Sigil> {
        let row_id = self.next_rowid;
        self.next_rowid.increment();
        self.row_m.insert(row_id, row);
        row_id
    }
    /// Selects a Row based on its row_id.
    pub fn select_by_row_id(&self, row_id: RowId<Sigil>) -> Option<&Row> {
        self.row_m.get(&row_id)
    }
    /// Iterate over all (row_id, row) pairs in this Table in unspecified order.
    pub fn row_iter(&self) -> std::collections::hash_map::Iter<'_, RowId<Sigil>, Row> {
        self.row_m.iter()
    }
    #[allow(dead_code)]
    pub fn insert_with_index_1<IndexSigil1: SigilT, IndexKey1: IndexKeyT>(
        &mut self,
        row: Row,
        index_1: &mut Index<IndexSigil1, Sigil, IndexKey1>,
    ) -> TableResult<RowId<Sigil>>
    where
        Row: IndexedRowT<IndexSigil1, IndexKey = IndexKey1>,
    {
        // First check that it's not in the index.
        let index_key_1 = row.index_key();
        if index_1.select(self, &index_key_1).is_some() {
            return Err("index key already exists in table".into());
        }
        let row_id = self.insert(row);
        index_1.insert_existing_row(row_id, index_key_1)?;
        Ok(row_id)
    }
    #[allow(dead_code)]
    pub fn insert_with_index_2<
        IndexSigil1: SigilT,
        IndexKey1: IndexKeyT,
        IndexSigil2: SigilT,
        IndexKey2: IndexKeyT,
    >(
        &mut self,
        row: Row,
        index_1: &mut Index<IndexSigil1, Sigil, IndexKey1>,
        index_2: &mut Index<IndexSigil2, Sigil, IndexKey2>,
    ) -> TableResult<RowId<Sigil>>
    where
        Row: IndexedRowT<IndexSigil1, IndexKey = IndexKey1>
            + IndexedRowT<IndexSigil2, IndexKey = IndexKey2>,
    {
        // First check that it's not in the indexes.
        let index_key_1 = <Row as IndexedRowT<IndexSigil1>>::index_key(&row);
        if index_1.select(self, &index_key_1).is_some() {
            return Err("index key 1 already exists in table".into());
        }
        let index_key_2 = <Row as IndexedRowT<IndexSigil2>>::index_key(&row);
        if index_2.select(self, &index_key_2).is_some() {
            return Err("index key 2 already exists in table".into());
        }
        let row_id = self.insert(row);
        index_1.insert_existing_row(row_id, index_key_1)?;
        index_2.insert_existing_row(row_id, index_key_2)?;
        Ok(row_id)
    }
    pub fn insert_with_index_3<
        IndexSigil1: SigilT,
        IndexKey1: IndexKeyT,
        IndexSigil2: SigilT,
        IndexKey2: IndexKeyT,
        IndexSigil3: SigilT,
        IndexKey3: IndexKeyT,
    >(
        &mut self,
        row: Row,
        index_1: &mut Index<IndexSigil1, Sigil, IndexKey1>,
        index_2: &mut Index<IndexSigil2, Sigil, IndexKey2>,
        index_3: &mut Index<IndexSigil3, Sigil, IndexKey3>,
    ) -> TableResult<RowId<Sigil>>
    where
        Row: IndexedRowT<IndexSigil1, IndexKey = IndexKey1>
            + IndexedRowT<IndexSigil2, IndexKey = IndexKey2>
            + IndexedRowT<IndexSigil3, IndexKey = IndexKey3>,
    {
        // First check that it's not in the indexes.
        let index_key_1 = <Row as IndexedRowT<IndexSigil1>>::index_key(&row);
        if index_1.select(self, &index_key_1).is_some() {
            return Err("index key 1 already exists in table".into());
        }
        let index_key_2 = <Row as IndexedRowT<IndexSigil2>>::index_key(&row);
        if index_2.select(self, &index_key_2).is_some() {
            return Err("index key 2 already exists in table".into());
        }
        let index_key_3 = <Row as IndexedRowT<IndexSigil3>>::index_key(&row);
        if index_3.select(self, &index_key_3).is_some() {
            return Err("index key 3 already exists in table".into());
        }
        let row_id = self.insert(row);
        index_1.insert_existing_row(row_id, index_key_1)?;
        index_2.insert_existing_row(row_id, index_key_2)?;
        index_3.insert_existing_row(row_id, index_key_3)?;
        Ok(row_id)
    }
}

pub trait IndexKeyT: Clone + Ord {}

impl<T: Clone + Ord> IndexKeyT for T {}

/// The Sigil type is meant to represent the "name" of the index.
// TODO: Figure out how it's possible to avoid copying stuff to produce the IndexKey.
pub trait IndexedRowT<Sigil: SigilT> {
    type IndexKey: IndexKeyT;
    fn index_key(&self) -> Self::IndexKey;
}

/// Provides an ordered, "unique constraint" index into a Table.
#[derive(Clone, Debug)]
pub struct Index<IndexSigil: SigilT, TableSigil: SigilT, IndexKey: IndexKeyT> {
    index_m: BTreeMap<IndexKey, RowId<TableSigil>>,
    index_sigil: std::marker::PhantomData<IndexSigil>,
}

impl<IndexSigil: SigilT, TableSigil: SigilT, IndexKey: IndexKeyT>
    Index<IndexSigil, TableSigil, IndexKey>
{
    pub fn new() -> Self {
        Self {
            index_m: BTreeMap::new(),
            index_sigil: Default::default(),
        }
    }
    // /// Returns the row_id.
    // pub fn insert<Row: Clone + IndexedRowT<IndexSigil, IndexKey = IndexKey>>(
    //     &mut self,
    //     table: &mut Table<TableSigil, Row>,
    //     row: Row,
    // ) -> TableResult<RowId<TableSigil>> {
    //     let index_key = row.index_key();
    //     match self.index_m.get(&index_key) {
    //         Some(_) => Err("index key already exists in table".into()),
    //         None => {
    //             let row_id = table.insert(row);
    //             self.index_m.insert(index_key, row_id);
    //             Ok(row_id)
    //         }
    //     }
    // }
    /// Indexes a row that already exists in the table.
    fn insert_existing_row(
        &mut self,
        row_id: RowId<TableSigil>,
        index_key: IndexKey,
    ) -> TableResult<()> {
        match self.index_m.get(&index_key) {
            Some(_) => Err("index key already exists in table".into()),
            None => {
                self.index_m.insert(index_key, row_id);
                Ok(())
            }
        }
    }
    pub fn select<'r, Row: Clone + IndexedRowT<IndexSigil>>(
        &self,
        table: &'r Table<TableSigil, Row>,
        index_key: &IndexKey,
    ) -> Option<(RowId<TableSigil>, &'r Row)> {
        match self.index_m.get(index_key) {
            Some(&row_id) => {
                let row = table
                    .select_by_row_id(row_id)
                    .expect("programmer error: table and index are inconsistent");
                Some((row_id, row))
            }
            None => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TableWithPrimaryKey<
    Sigil: SigilT,
    PrimaryKey: PrimaryKeyT,
    Row: Clone + RowT<PrimaryKey>,
> {
    table: Table<Sigil, Row>,
    index_m: HashMap<PrimaryKey, RowId<Sigil>>,
}

impl<Sigil: SigilT, PrimaryKey: PrimaryKeyT, Row: Clone + RowT<PrimaryKey>>
    TableWithPrimaryKey<Sigil, PrimaryKey, Row>
{
    pub fn new() -> Self {
        Self {
            table: Table::new(),
            index_m: HashMap::new(),
        }
    }
    /// Returns the row_id.
    pub fn insert(&mut self, row: Row, on_conflict: OnConflict) -> TableResult<RowId<Sigil>> {
        let primary_key = row.primary_key();
        match self.index_m.get(primary_key) {
            Some(&existing_rowid) => {
                // There's a conflict.
                match on_conflict {
                    OnConflict::Abort => Err("row already exists".into()),
                    OnConflict::Ignore => Ok(existing_rowid),
                    OnConflict::Replace => {
                        *self.table.row_m.get_mut(&existing_rowid).unwrap() = row;
                        Ok(existing_rowid)
                    }
                }
            }
            None => {
                // There's no conflict, so just insert.
                let primary_key = row.primary_key().clone();
                let row_id = self.table.insert(row);
                self.index_m.insert(primary_key, row_id);
                Ok(row_id)
            }
        }
    }
    /// row_updater is what defines the update operation, however it may not alter its primary key.
    pub fn update(
        &mut self,
        primary_key: &PrimaryKey,
        row_updater: impl Fn(&Row) -> TableResult<Row>,
    ) -> TableResult<()> {
        let row_id = *self
            .index_m
            .get(primary_key)
            .ok_or_else(|| "row not found")?;
        let row = self.table.select_by_row_id(row_id).unwrap();
        let updated_row = row_updater(row)?;
        if updated_row.primary_key() != primary_key {
            return Err("primary key cannot be changed".into());
        }
        *self.table.row_m.get_mut(&row_id).unwrap() = updated_row;
        Ok(())
    }
    #[allow(dead_code)]
    pub fn remove(&mut self, primary_key: &PrimaryKey) -> TableResult<()> {
        match self.index_m.remove(primary_key) {
            Some(row_id) => {
                self.table.row_m.remove(&row_id);
                Ok(())
            }
            None => Err("row not found".into()),
        }
    }
    pub fn select(&self, primary_key: &PrimaryKey) -> Option<(RowId<Sigil>, &Row)> {
        match self.index_m.get(primary_key) {
            Some(&row_id) => {
                let row = self.table.select_by_row_id(row_id).unwrap();
                Some((row_id, row))
            }
            None => None,
        }
    }
    pub fn row_iter(&self) -> std::collections::hash_map::Iter<'_, RowId<Sigil>, Row> {
        self.table.row_iter()
    }
}
