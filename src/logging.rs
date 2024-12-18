use env_logger::{Builder, Env};
use std::fs::File;
use std::io::Write;

pub struct Logging {
    pub file: File,
}

impl Logging {
    pub fn new(logging_file: &str) -> Self {
        let file = File::options()
            .append(true)
            .create(true)
            .open(logging_file)
            .expect("Failed to open log file");

        let logging = Self { file };

        Builder::from_env(Env::default().default_filter_or("info"))
            .format(move |buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
            .target(env_logger::Target::Stdout)
            .write_style(env_logger::WriteStyle::Always)
            .init();
        log::set_boxed_logger(Box::new(env_logger::Logger::from_default_env()))
            .map(|()| log::set_max_level(log::LevelFilter::Info))
            .expect("Failed to set logger");

        logging
    }
}
