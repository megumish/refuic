#[derive(thiserror::Error, Debug)]
pub enum RepositoryError {
    #[error("not found")]
    NotFound,
    #[error("internal error")]
    InternalError { description: String },
}
