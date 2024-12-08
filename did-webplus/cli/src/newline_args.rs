#[derive(clap::Args, Debug)]
pub struct NewlineArgs {
    /// Do not print a newline at the end of the output.
    #[arg(env = "DID_WEBPLUS_NO_NEWLINE", short, long)]
    pub no_newline: bool,
}

impl NewlineArgs {
    pub fn print_newline_if_necessary(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if !self.no_newline {
            out.write_all(b"\n")?;
        }
        Ok(())
    }
}
