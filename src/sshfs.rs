use async_trait::async_trait;
use nfsserve::{
    nfs::{fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, specdata3},
    vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities},
};
use russh_sftp::client::SftpSession;

pub struct Sshfs {
    sftp: SftpSession,
    rootdir: fileid3,
    remote_root: String,
}

impl Sshfs {
    pub fn new(sftp: SftpSession, remote_root: String) -> Self {
        Sshfs {
            sftp: sftp,
            rootdir: 0,
            remote_root: remote_root,
        }
    }
}

#[async_trait]
impl NFSFileSystem for Sshfs {
    fn root_dir(&self) -> fileid3 {
        self.rootdir
    }

    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadOnly
    }

    async fn write(&self, _id: fileid3, _offset: u64, _data: &[u8]) -> Result<fattr3, nfsstat3> {
        return Err(nfsstat3::NFS3ERR_ROFS);
    }

    async fn create(
        &self,
        _dirid: fileid3,
        _filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        return Err(nfsstat3::NFS3ERR_ROFS);
    }

    async fn create_exclusive(
        &self,
        _dirid: fileid3,
        _filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn lookup(&self, _dirid: fileid3, _filename: &filename3) -> Result<fileid3, nfsstat3> {
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        if id == 0 {
            let attr = fattr3 {
                ftype: ftype3::NF3DIR,
                mode: 0o777,
                nlink: 1,
                uid: 507,
                gid: 507,
                size: 0,
                used: 0,
                rdev: specdata3::default(),
                fsid: 0,
                fileid: id,
                atime: nfstime3::default(),
                mtime: nfstime3::default(),
                ctime: nfstime3::default(),
            };
            return Ok(attr);
        }
        return Err(nfsstat3::NFS3ERR_NOENT);
    }

    async fn setattr(&self, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn read(
        &self,
        _id: fileid3,
        _offset: u64,
        _count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        eprintln!(
            "Read dir for id {}, {}, {}",
            dirid, start_after, max_entries
        );
        let entries: Vec<DirEntry> = self
            .sftp
            .read_dir(&self.remote_root)
            .await
            .unwrap()
            .take(max_entries)
            .enumerate()
            .map(|(id, entry)| {
                let attr = fattr3 {
                    ftype: match entry.file_type() {
                        russh_sftp::protocol::FileType::Dir => ftype3::NF3DIR,
                        russh_sftp::protocol::FileType::Symlink => ftype3::NF3LNK,
                        russh_sftp::protocol::FileType::File => ftype3::NF3REG,
                        russh_sftp::protocol::FileType::Other => ftype3::NF3REG,
                    },
                    mode: entry.metadata().permissions.unwrap(),
                    nlink: 1,
                    uid: entry.metadata().uid.unwrap_or(501),
                    gid: entry.metadata().gid.unwrap_or(501),
                    size: entry.metadata().size.unwrap_or(0),
                    used: 0,
                    rdev: specdata3::default(),
                    fsid: 0,
                    fileid: id as u64,
                    atime: nfstime3::default(),
                    mtime: nfstime3::default(),
                    ctime: nfstime3::default(),
                };
                DirEntry {
                    fileid: id as u64,
                    name: entry.file_name().as_bytes().into(),
                    attr: attr,
                }
            })
            .collect();
        let ret = ReadDirResult {
            entries: entries,
            end: true,
        };

        Ok(ret)
    }

    #[allow(unused)]
    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        return Err(nfsstat3::NFS3ERR_ROFS);
    }

    #[allow(unused)]
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        return Err(nfsstat3::NFS3ERR_ROFS);
    }

    #[allow(unused)]
    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    #[allow(unused)]
    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readlink(&self, _id: fileid3) -> Result<nfspath3, nfsstat3> {
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }
}
