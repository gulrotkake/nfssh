use std::sync::Arc;

use async_trait::async_trait;

use clap::Parser;
use clap_derive::Parser;
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use russh::client::Handle;
use russh_keys::key::PublicKey;
use russh_sftp::client::SftpSession;
use sshfs::SshFs;
use tracing::Level;
mod sshfs;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(default_value_t = whoami::username(), short, long)]
    username: String,

    #[arg(long)]
    password: Option<String>,

    #[arg(default_value = ".", short, long)]
    directory: String,

    #[arg(default_value_t = 22, short, long)]
    port: u16,

    #[arg(long)]
    log_level: Option<Level>,

    #[arg(long)]
    host: String,
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

const HOSTPORT: u32 = 11111;
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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_max_level(args.log_level.unwrap_or(tracing::Level::INFO))
        .with_writer(std::io::stderr)
        .init();

    // Setup SFTP client
    let config = russh::client::Config::default();
    let mut agent = russh_keys::agent::client::AgentClient::connect_env()
        .await
        .unwrap();
    let identities = agent.request_identities().await.unwrap();

    let sh = Client {
        host: args.host.to_owned(),
        port: args.port,
    };
    let mut session = russh::client::connect(Arc::new(config), (args.host, args.port), sh)
        .await
        .unwrap();
    let mut iter = identities.iter();
    let authenticated = loop {
        match iter.next() {
            Some(id) => {
                if try_authenticate(&mut session, id.to_owned(), &args.username).await {
                    break true;
                }
            }
            None => break false,
        }
    };
    if !authenticated && args.password.is_some() {
        if !session
            .authenticate_password(args.username, args.password.unwrap())
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

    // Setup NFS bridge
    let listener = NFSTcpListener::bind(
        &format!("127.0.0.1:{HOSTPORT}"),
        SshFs::new(sftp, args.directory.into()),
    )
    .await
    .unwrap();
    listener.handle_forever().await.unwrap();
}
