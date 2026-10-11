use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|_| "could not open file")?;
    let mut bytes = Vec::new();
    file.take((cap + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read file")?;
    if bytes.len() > cap {
        return Err("file exceeds permitted size");
    }
    Ok(bytes)
}

/// A verified artifact is published only after a complete write, never over an old output.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|_| "could not create output directory")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| "could not create temporary output")?;
    temporary
        .write_all(bytes)
        .map_err(|_| "could not write output")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "could not flush output")?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| "output exists or could not be published")?;
    Ok(())
}
