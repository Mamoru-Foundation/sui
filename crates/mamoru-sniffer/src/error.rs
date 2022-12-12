use mamoru_core::{DataError, SnifferError};

#[derive(thiserror::Error, Debug)]
pub enum SuiSnifferError {
    #[error(transparent)]
    SnifferError(#[from] SnifferError),

    #[error(transparent)]
    DataError(#[from] DataError),
}
