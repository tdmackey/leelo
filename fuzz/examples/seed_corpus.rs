fn main() -> std::io::Result<()> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    for (target, name, bytes) in leelo_fuzz::seeds() {
        let directory = root.join(target);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(directory.join(name), bytes)?;
    }
    Ok(())
}
