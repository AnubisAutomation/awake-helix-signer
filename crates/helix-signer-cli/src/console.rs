//! Terminal input and output.
//!
//! Lines go to stdout. Visible questions are written to stdout and read from
//! stdin (like Python's ``input()``). Secrets are read with a hidden prompt
//! from the terminal; when stdin is not a terminal (automation, tests, a
//! session without a controlling terminal) the prompt goes to stderr and the
//! secret is one line of stdin, like Python's ``getpass`` fallback.

use std::io::{BufRead, IsTerminal, Write};

use helix_signer_core::{Error, Prompter, Result, Zeroizing};

/// The real terminal.
#[derive(Clone, Copy, Debug, Default)]
pub struct Console;

fn read_line() -> Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    let read = std::io::stdin().lock().read_line(&mut line).map_err(|error| Error::io(error.to_string()))?;
    if read == 0 {
        return Err(Error::cancelled("Input closed."));
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

impl Console {
    /// The process's terminal.
    pub fn terminal() -> Console {
        Console
    }

    /// Print one line.
    pub fn out(&self, text: &str) {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{text}");
        let _ = stdout.flush();
    }

    /// Visible input.
    pub fn ask(&self, prompt: &str) -> Result<String> {
        {
            let mut stdout = std::io::stdout().lock();
            let _ = write!(stdout, "{prompt}");
            let _ = stdout.flush();
        }
        read_line().map(|line| line.to_string())
    }
}

impl Prompter for Console {
    fn say(&self, text: &str) {
        self.out(text);
    }

    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>> {
        if std::io::stdin().is_terminal() {
            return match rpassword::prompt_password(prompt) {
                Ok(secret) => Ok(Zeroizing::new(secret)),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Err(Error::cancelled("Input closed.")),
                Err(error) => Err(Error::io(error.to_string())),
            };
        }
        {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "{prompt}");
            let _ = stderr.flush();
        }
        read_line()
    }

    fn ask(&self, prompt: &str) -> Result<String> {
        Console::ask(self, prompt)
    }
}
