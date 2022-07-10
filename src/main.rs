use crate::everything::Everything;

mod everything {
    use std::fmt::Display;
    use std::ptr::null;
    use enumflags2::{bitflags, BitFlags};
    use everything_sys::*;
    use once_cell::sync::{OnceCell};
    use parking_lot::RwLock;
    use widestring::U16CString;
    use winapi::shared::minwindef::{BOOL, DWORD, TRUE};
    use winapi::shared::windef::HWND;
    use thiserror::Error;

    //error type
    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Everything Error - {0}")]
        EverythingError(EverythingError),
        #[error("WideString Error - {0}")]
        WideStringError(#[from] WideStringError),
        #[error("Unknown Variant Type for {0} - {1}")]
        UnknownVariant(String, u32),
    }

    #[derive(Error, Debug)]
    pub enum WideStringError {
        #[error("Nul Error - {0}")]
        NulError(#[from] widestring::error::ContainsNul<u16>),
        #[error("Utf16Error Error - {0}")]
        Utf16Error(#[from] widestring::error::Utf16Error),
    }

    type Result<T> = std::result::Result<T, Error>;


    #[repr(u8)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum EverythingError {
        MemoryError,
        IpcError,
        RegisterClassExError,
        CreateWindowError,
        CreateThreadError,
        InvalidIndexError,
        InvalidCallError,
    }

    impl EverythingError {
        fn from_u32(code: u32) -> Result<Self> {
            match code {
                1 => Ok(EverythingError::MemoryError),
                2 => Ok(EverythingError::IpcError),
                3 => Ok(EverythingError::RegisterClassExError),
                4 => Ok(EverythingError::CreateWindowError),
                5 => Ok(EverythingError::CreateThreadError),
                6 => Ok(EverythingError::InvalidIndexError),
                7 => Ok(EverythingError::InvalidCallError),
                _ => Err(Error::UnknownVariant("EverythingError".to_string(), code)),
            }
        }

        fn to_u32(self) -> u32 {
            match self {
                EverythingError::MemoryError => 1,
                EverythingError::IpcError => 2,
                EverythingError::RegisterClassExError => 3,
                EverythingError::CreateWindowError => 4,
                EverythingError::CreateThreadError => 5,
                EverythingError::InvalidIndexError => 6,
                EverythingError::InvalidCallError => 7,
            }
        }
    }

    impl Display for EverythingError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }


    #[repr(u8)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum SortType {
        Ascending = 0,
        Descending = 1,
    }

    impl SortType {
        fn from_u32(code: u32) -> Result<Self> {
            match code {
                0 => Ok(SortType::Ascending),
                1 => Ok(SortType::Descending),
                _ => Err(Error::UnknownVariant("SortType".to_string(), code)),
            }
        }

        fn to_u32(self) -> u32 {
            match self {
                SortType::Ascending => 0,
                SortType::Descending => 1,
            }
        }
    }


    #[repr(u8)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum SortBy {
        Name = 0,
        Path = 2,
        Size = 4,
        Extension = 6,
        TypeName = 8,
        DateCreated = 10,
        DateModified = 12,
        Attributes = 14,
        FileListFilename = 16,
        RunCount = 18,
        DateRecentlyChanged = 20,
        DateAccessed = 22,
        DateRun = 24,
    }

    impl SortBy {
fn from_u32(code: u32) -> Result<Self> {
            match code {
                0 => Ok(SortBy::Name),
                2 => Ok(SortBy::Path),
                4 => Ok(SortBy::Size),
                6 => Ok(SortBy::Extension),
                8 => Ok(SortBy::TypeName),
                10 => Ok(SortBy::DateCreated),
                12 => Ok(SortBy::DateModified),
                14 => Ok(SortBy::Attributes),
                16 => Ok(SortBy::FileListFilename),
                18 => Ok(SortBy::RunCount),
                20 => Ok(SortBy::DateRecentlyChanged),
                22 => Ok(SortBy::DateAccessed),
                24 => Ok(SortBy::DateRun),
                _ => Err(Error::UnknownVariant("SortBy".to_string(), code)),
            }
        }

        fn to_u32(self) -> u32 {
            match self {
                SortBy::Name => 0,
                SortBy::Path => 2,
                SortBy::Size => 4,
                SortBy::Extension => 6,
                SortBy::TypeName => 8,
                SortBy::DateCreated => 10,
                SortBy::DateModified => 12,
                SortBy::Attributes => 14,
                SortBy::FileListFilename => 16,
                SortBy::RunCount => 18,
                SortBy::DateRecentlyChanged => 20,
                SortBy::DateAccessed => 22,
                SortBy::DateRun => 24,
            }
        }
    }

    #[bitflags]
    #[repr(u32)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum RequestFlags {
        FileName = 0x00000001,
        Path = 0x00000002,
        FullPathAndFileName = 0x00000004,
        Extension = 0x00000008,
        Size = 0x00000010,
        DateCreated = 0x00000020,
        DateModified = 0x00000040,
        DateAccessed = 0x00000080,
        Attributes = 0x00000100,
        FileListFileName = 0x00000200,
        RunCount = 0x00000400,
        DateRun = 0x00000800,
        DateRecentlyChanged = 0x00001000,
        HighlightedFileName = 0x00002000,
        HighlightedPath = 0x00004000,
        HighlightedFullPathAndFileName = 0x00008000,
    }


    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum TargetMachine {
        X86 = 1,
        X64 = 2,
        ARM = 3,
    }

    impl TargetMachine {
        fn from_u32(code: u32) -> Result<Self> {
            match code {
                1 => Ok(TargetMachine::X86),
                2 => Ok(TargetMachine::X64),
                3 => Ok(TargetMachine::ARM),
                _ => Err(Error::UnknownVariant("TargetMachine".to_string(), code)),
            }
        }

        fn to_u32(self) -> u32 {
            match self {
                TargetMachine::X86 => 1,
                TargetMachine::X64 => 2,
                TargetMachine::ARM => 3,
            }
        }
    }

    pub struct Everything {
        _private: (),
    }


    macro_rules! generate_set_bool {
            ($name:ident, $method:ident) => {
                pub fn $name(&mut self, enable: bool) -> Result<()> {
                    unsafe {
                            $method(enable as BOOL);
                        }

                        self.get_last_error()
                }
            };
    }

    macro_rules! generate_set_u32 {
            ($name:ident, $method:ident) => {
                pub fn $name(&mut self, value: u32) -> Result<()> {
                    unsafe {
                            $method(value as DWORD);
                        }

                        self.get_last_error()
                }
            };
    }

    macro_rules! generate_set_null {
            ($name:ident, $method:ident) => {
                pub fn $name(&mut self) -> Result<()> {
                    unsafe {
                            $method();
                        }

                        self.get_last_error()
                }
            };
    }

    macro_rules! generate_get_u32 {
            ($name:ident, $method:ident) => {
                pub fn $name(&self) -> Result<u32> {
                    let value = unsafe {
                            $method()
                    };

                    self.get_last_error().map(|_| value as u32)
                }
            };
    }

    macro_rules! generate_get_bool {
            ($name:ident, $method:ident) => {
                pub fn $name(&self) -> Result<bool> {
                    let value = unsafe {
                            $method()
                    };

                    self.get_last_error().map(|_| value == TRUE)
                }
            };
    }

    macro_rules! generate_get_result_bool {
            ($name:ident, $method:ident) => {
                pub fn $name(&self, index: u32) -> Result<bool> {
                    let value = unsafe {
                            $method(index as DWORD)
                    };

                    self.get_last_error().map(|_| value == TRUE)
                }
            };
    }

    macro_rules! generate_get_result_u32 {
            ($name:ident, $method:ident) => {
                pub fn $name(&self, index: u32) -> Result<u32> {
                    let value = unsafe {
                            $method(index as DWORD)
                    };

                    self.get_last_error().map(|_| value as u32)
                }
            };
    }

    macro_rules! generate_get_result_string {
            ($name:ident, $method:ident) => {
                pub fn $name(&self, index: u32) -> Result<String> {
                   let mut res = null();
                    unsafe {
                        res = $method(index);
                    }
                    if res.is_null() {
                        return self.get_last_error().map(|_| String::new());
                    }
                    Ok(unsafe {
                        let res = U16CString::from_ptr_str(res);
                        res.to_string()
                    }.map_err(WideStringError::from)?)
                }
            };
    }

    impl Everything {
        pub fn get() -> &'static RwLock<Everything> {
            static INSTANCE: OnceCell<RwLock<Everything>> = OnceCell::new();
            INSTANCE.get_or_init(|| {
                RwLock::new(Everything { _private: () })
            })
        }

        pub fn get_last_error(&self) -> Result<()> {
            let error = unsafe {
                Everything_GetLastError()
            };
            if error == 0 {
                Ok(())
            } else {
                Err(Error::EverythingError(EverythingError::from_u32(error)?))
            }
        }

        generate_set_bool!(set_match_path, Everything_SetMatchPath);
        generate_set_bool!(set_match_case, Everything_SetMatchCase);
        generate_set_bool!(set_match_whole_word, Everything_SetMatchWholeWord);
        generate_set_bool!(set_regex, Everything_SetRegex);

        generate_set_u32!(set_max, Everything_SetMax);
        generate_set_u32!(set_offset, Everything_SetOffset);
        generate_set_u32!(set_reply_id, Everything_SetReplyID);

        generate_set_null!(reset, Everything_Reset);
        generate_set_null!(cleanup, Everything_CleanUp);
        generate_set_null!(delete_run_history, Everything_DeleteRunHistory);
        generate_set_null!(save_run_history, Everything_SaveRunHistory);
        generate_set_null!(save_db, Everything_SaveDB);
        generate_set_null!(update_all_folder_indexes, Everything_UpdateAllFolderIndexes);
        generate_set_null!(rebuild_db, Everything_RebuildDB);


        pub fn set_search(&mut self, search: &str) -> Result<()> {
            let search = U16CString::from_str(search).map_err(WideStringError::from)?;
            unsafe {
                Everything_SetSearchW(search.as_ptr());
            }

            self.get_last_error()
        }

        pub fn set_reply_window(&mut self, window: HWND) -> Result<()> {
            unsafe {
                Everything_SetReplyWindow(window);
            }

            self.get_last_error()
        }

        pub fn set_sort(&mut self, by: SortBy, sort: SortType) -> Result<()> {
            unsafe {
                let converted_sort = 1 + (by as DWORD) + (sort as DWORD);
                Everything_SetSort(converted_sort);
            }
            self.get_last_error()
        }

        pub fn set_request_flags(&mut self, flags: BitFlags<RequestFlags>) -> Result<()> {
            unsafe {
                Everything_SetRequestFlags(flags.bits() as DWORD);
            }

            self.get_last_error()
        }

        pub fn query(&mut self, wait: bool) -> Result<()> {
            unsafe {
                Everything_QueryW(wait as BOOL);
            }

            self.get_last_error()
        }

        fn get_search(&self) -> Result<String> {
            let mut res = null();
            unsafe {
                res = Everything_GetSearchW();
            }
            if res.is_null() {
                return self.get_last_error().map(|_| String::new());
            }
            Ok(unsafe {
                let res = U16CString::from_ptr_str(res);
                res.to_string()
            }.map_err(WideStringError::from)?)
        }

        generate_get_bool!(get_match_path, Everything_GetMatchPath);
        generate_get_bool!(get_match_case, Everything_GetMatchCase);
        generate_get_bool!(get_match_whole_word, Everything_GetMatchWholeWord);
        generate_get_bool!(get_regex, Everything_GetRegex);
        generate_get_bool!(is_admin, Everything_IsAdmin);
        generate_get_bool!(is_db_loaded, Everything_IsDBLoaded);


        generate_get_u32!(get_max, Everything_GetMax);
        generate_get_u32!(get_offset, Everything_GetOffset);
        generate_get_u32!(get_reply_id, Everything_GetReplyID);
        generate_get_u32!(get_major_version, Everything_GetMajorVersion);
        generate_get_u32!(get_minor_version, Everything_GetMinorVersion);
        generate_get_u32!(get_build_number, Everything_GetBuildNumber);
        generate_get_u32!(get_revision, Everything_GetRevision);


        generate_get_u32!(get_visible_results_count, Everything_GetNumResults);
        generate_get_u32!(get_visible_file_results_count, Everything_GetNumFileResults);
        generate_get_u32!(get_visible_folder_results_count, Everything_GetNumFolderResults);
        generate_get_u32!(get_total_results_count, Everything_GetTotResults);
        generate_get_u32!(get_total_file_results_count, Everything_GetTotFileResults);
        generate_get_u32!(get_total_folder_results_count, Everything_GetTotFolderResults);

        generate_get_result_bool!(is_volume_result, Everything_IsVolumeResult);
        generate_get_result_bool!(is_folder_result, Everything_IsFolderResult);
        generate_get_result_bool!(is_file_result, Everything_IsFileResult);

        generate_get_result_string!(get_result_file_name, Everything_GetResultFileNameW);
        generate_get_result_string!(get_result_path, Everything_GetResultPathW);
        generate_get_result_string!(get_result_extension, Everything_GetResultExtensionW);





        fn get_reply_window(&self) -> Result<HWND> {
            let res = unsafe {
                Everything_GetReplyWindow()
            };
            self.get_last_error().map(|_| res)
        }

        fn get_sort(&self) -> Result<(SortBy, SortType)> {
            let res = unsafe {
                Everything_GetSort()
            };
            self.get_last_error().and_then(|_| {
                let by = SortBy::from_u32(res >> 1)?;
                let sort = SortType::from_u32(res & 1 )?;
                Ok((by, sort))
            })
        }

        fn get_request_flags(&self) -> Result<BitFlags<RequestFlags>> {
            let res = unsafe {
                Everything_GetRequestFlags()
            };
            self.get_last_error().and_then(|_| BitFlags::<RequestFlags>::from_bits(res).map_err(|e|
                Error::UnknownVariant("RequestFlags".to_string(), e.invalid_bits())))
        }

        fn get_target_machine(&self) -> Result<TargetMachine> {
            let res = unsafe {
                Everything_GetTargetMachine()
            };
            self.get_last_error().and_then(|_| TargetMachine::from_u32(res))
        }
    }
}

pub fn search(query: &str) {
    let everything = Everything::get();
    {
        let mut guard = everything.write();
        guard.set_search(query).unwrap();
        guard.set_max(1).unwrap();
        guard.query(true).unwrap();
    }
    let reader = everything.read();

    for i in 0..reader.get_visible_results_count().unwrap() {
        println!("{}\\{} - is file: {}", reader.get_result_path(i).unwrap(), reader
            .get_result_file_name(i)
            .unwrap(), reader.is_file_result(i).unwrap());
    }
}

pub fn main() {
    search("notepad*")
}
