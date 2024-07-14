use std::{sync::Arc, time::Duration};

use async_trait::async_trait;

use clap::Parser;
use clap_derive::Parser;
use coarsetime::Instant;
use dashmap::DashMap;
use nfsserve::{
    nfs::{fattr3, fileid3},
    tcp::{NFSTcp, NFSTcpListener},
};
use russh::client::Handle;
use russh_keys::key::PublicKey;
use russh_sftp::client::SftpSession;
use sshfs::SshFs;
use tokio::{task, time::sleep};
use tracing::{info, Level};
mod sshfs;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    password: Option<String>,

    #[arg(default_value = "5", short, long)]
    cache_refresh: u16,

    #[arg(default_value = "180", short, long)]
    cache_expunge: u32,

    #[arg(default_value_t = 22, short, long)]
    port: u16,

    #[arg(default_value_t = 11111, short, long)]
    nfs_port: u16,

    #[arg(long)]
    log_level: Option<Level>,

    ssh: String,
}

#[derive(Debug, Clone)]
struct SshParseError;

impl std::fmt::Display for SshParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Failed to parse SSH string, must be of form [user@]host:[path]"
        )
    }
}

struct Client {
    host: String,
    port: u16,
}

#[async_trait]
impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        russh_keys::check_known_hosts(&self.host, self.port, &server_public_key)
            .or(Err(Self::Error::UnknownKey))
    }
}

async fn try_authenticate(session: &mut Handle<Client>, id: PublicKey, username: &String) -> bool {
    let agent = russh_keys::agent::client::AgentClient::connect_env()
        .await
        .unwrap();
    session
        .authenticate_future(username, id, agent)
        .await
        .1
        .unwrap()
}

fn parse_ssh_string(ssh_string: &str) -> Result<(Option<&str>, &str, &str), SshParseError> {
    let (user, host_path) = match ssh_string.split_once('@') {
        Some((user, host_path)) => (Some(user), host_path),
        None => (None, ssh_string),
    };

    let (host, path) = host_path.split_once(':').ok_or(SshParseError)?;

    Ok((user, host, path.is_empty().then_some(".").unwrap_or(&path)))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_max_level(args.log_level.unwrap_or(tracing::Level::INFO))
        .with_writer(std::io::stderr)
        .init();

    let (user, host, path) = parse_ssh_string(&args.ssh).unwrap();
    let username = user.map(str::to_string).unwrap_or_else(whoami::username);
    // Setup SFTP client
    let config = russh::client::Config::default();
    let mut agent = russh_keys::agent::client::AgentClient::connect_env()
        .await
        .unwrap();
    let identities = agent.request_identities().await.unwrap();

    let sh = Client {
        host: host.to_string(),
        port: args.port,
    };
    let mut session = russh::client::connect(Arc::new(config), (host.to_string(), args.port), sh)
        .await
        .unwrap();
    let mut iter = identities.iter();
    let authenticated = loop {
        match iter.next() {
            Some(id) => {
                if try_authenticate(&mut session, id.to_owned(), &username).await {
                    break true;
                }
            }
            None => break false,
        }
    };
    if !authenticated && args.password.is_some() {
        if !session
            .authenticate_password(username, args.password.unwrap())
            .await
            .unwrap()
        {
            panic!("Failed to connect SSH");
        }
    }
    let channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = SftpSession::new(channel.into_stream()).await.unwrap();
    sftp.set_timeout(300).await;
    let cache: Arc<DashMap<fileid3, (fattr3, Instant, String)>> = Arc::new(DashMap::new());

    let interval = Duration::from_secs(args.cache_expunge as u64); // Change this to the desired interval

    let expunge_cache = cache.clone();
    task::spawn(async move {
        loop {
            sleep(interval).await;
            expunge_cache
                .retain(|_, v| v.1.elapsed_since_recent().as_secs() < args.cache_expunge as u64);
            info!("Expunging stale element in cache");
        }
    });

    // Setup NFS bridge
    let listener = NFSTcpListener::bind(
        &format!("127.0.0.1:{0}", args.nfs_port),
        SshFs::new(sftp, path.into(), cache, args.cache_refresh),
    )
    .await
    .unwrap();
    listener.handle_forever().await.unwrap();
}
