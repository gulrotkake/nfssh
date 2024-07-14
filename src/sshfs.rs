// Heavily based on https://github.com/xetdata/nfsserve/blob/main/examples/mirrorfs.rs

use std::collections::{BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::io::SeekFrom;
use std::ops::Bound;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use coarsetime::Instant;
use dashmap::DashMap;
use intaglio::osstr::SymbolTable;
use intaglio::Symbol;
use russh_sftp::client::fs::Metadata;
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::debug;

use nfsserve::fs_util::*;
use nfsserve::nfs::*;
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};

#[derive(Debug, Clone)]
struct FSEntry {
    name: Vec<Symbol>,
    fsmeta: fattr3,
    children_meta: fattr3,
    children: Option<BTreeSet<fileid3>>,
}

struct FSMap {
    root: PathBuf,
    next_fileid: AtomicU64,
    intern: SymbolTable,
    id_to_path: HashMap<fileid3, FSEntry>,
    path_to_id: HashMap<Vec<Symbol>, fileid3>,
}

fn metadata_to_fattr3(fid: fileid3, meta: &Metadata) -> Result<fattr3, nfsstat3> {
    Ok(fattr3 {
        ftype: match meta.file_type() {
            russh_sftp::protocol::FileType::Dir => ftype3::NF3DIR,
            russh_sftp::protocol::FileType::Symlink => ftype3::NF3LNK,
            russh_sftp::protocol::FileType::File => ftype3::NF3REG,
            russh_sftp::protocol::FileType::Other => ftype3::NF3REG,
        },
        mode: meta.permissions.ok_or(nfsstat3::NFS3ERR_IO)?,
        nlink: 1,
        uid: meta.uid.ok_or(nfsstat3::NFS3ERR_IO)?,
        gid: meta.gid.ok_or(nfsstat3::NFS3ERR_IO)?,
        size: meta.size.ok_or(nfsstat3::NFS3ERR_IO)?,
        used: 0,
        rdev: specdata3::default(),
        fsid: 0,
        fileid: fid,
        atime: nfstime3 {
            seconds: meta.atime.unwrap_or(0) as u32,
            nseconds: 0,
        },
        mtime: nfstime3 {
            seconds: meta.mtime.unwrap_or(0) as u32,
            nseconds: 0,
        },
        ctime: nfstime3::default(),
    })
}

enum RefreshResult {
    Delete,
    Reload,
    Noop,
}

impl FSMap {
    fn new(root: PathBuf) -> FSMap {
        let root_attr = fattr3 {
            ftype: ftype3::NF3DIR,
            mode: 0o777,
            nlink: 1,
            uid: 507,
            gid: 507,
            size: 0,
            used: 0,
            rdev: specdata3::default(),
            fsid: 1,
            fileid: 0,
            atime: nfstime3::default(),
            mtime: nfstime3::default(),
            ctime: nfstime3::default(),
        };

        let root_entry = FSEntry {
            name: Vec::new(),
            fsmeta: root_attr,
            children_meta: root_attr,
            children: None,
        };
        FSMap {
            root,
            next_fileid: AtomicU64::new(1),
            intern: SymbolTable::new(),
            id_to_path: HashMap::from([(0, root_entry)]),
            path_to_id: HashMap::from([(Vec::new(), 0)]),
        }
    }

    fn sym_to_path(&self, symlist: &[Symbol]) -> PathBuf {
        let mut ret = self.root.clone();
        for i in symlist.iter() {
            ret.push(self.intern.get(*i).unwrap());
        }
        ret
    }

    fn sym_to_fname(&self, symlist: &[Symbol]) -> OsString {
        if let Some(x) = symlist.last() {
            self.intern.get(*x).unwrap().into()
        } else {
            "".into()
        }
    }

    fn collect_all_children(&self, id: fileid3, ret: &mut Vec<fileid3>) {
        ret.push(id);
        if let Some(entry) = self.id_to_path.get(&id) {
            if let Some(ref ch) = entry.children {
                for i in ch.iter() {
                    self.collect_all_children(*i, ret);
                }
            }
        }
    }

    fn delete_entry<T>(&mut self, id: fileid3, cache: &DashMap<u64, T>) {
        let mut children = Vec::new();
        self.collect_all_children(id, &mut children);
        for i in children.iter() {
            if let Some(ent) = self.id_to_path.remove(i) {
                self.path_to_id.remove(&ent.name);
                cache.remove(&id);
            }
        }
    }

    fn find_entry(&self, id: fileid3) -> Result<FSEntry, nfsstat3> {
        Ok(self
            .id_to_path
            .get(&id)
            .ok_or(nfsstat3::NFS3ERR_NOENT)?
            .clone())
    }

    fn find_child(&self, id: fileid3, filename: &[u8]) -> Result<fileid3, nfsstat3> {
        let mut name = self
            .id_to_path
            .get(&id)
            .ok_or(nfsstat3::NFS3ERR_NOENT)?
            .name
            .clone();
        name.push(
            self.intern
                .check_interned(OsStr::from_bytes(filename))
                .ok_or(nfsstat3::NFS3ERR_NOENT)?,
        );
        Ok(*self.path_to_id.get(&name).ok_or(nfsstat3::NFS3ERR_NOENT)?)
    }

    async fn refresh_entry<T>(
        &mut self,
        sftp: &SftpSession,
        cache: &DashMap<fileid3, T>,
        id: fileid3,
    ) -> Result<RefreshResult, nfsstat3> {
        let entry = self
            .id_to_path
            .get(&id)
            .ok_or(nfsstat3::NFS3ERR_NOENT)?
            .clone();
        let path = self.sym_to_path(&entry.name);

        let fname = path.to_str().ok_or(nfsstat3::NFS3ERR_IO)?;

        if !sftp.try_exists(fname).await.or(Err(nfsstat3::NFS3ERR_IO))? {
            self.delete_entry(id, cache);
            return Ok(RefreshResult::Delete);
        }

        let meta = sftp
            .symlink_metadata(fname)
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let meta = metadata_to_fattr3(id, &meta).or(Err(nfsstat3::NFS3ERR_IO))?;
        if !fattr3_differ(&meta, &entry.fsmeta) {
            return Ok(RefreshResult::Noop);
        }

        // If we get here we have modifications
        if entry.fsmeta.ftype as u32 != meta.ftype as u32 {
            self.delete_entry(id, cache);
            return Ok(RefreshResult::Delete);
        }

        // update metadata
        self.id_to_path
            .get_mut(&id)
            .ok_or(nfsstat3::NFS3ERR_IO)?
            .fsmeta = meta;
        Ok(RefreshResult::Reload)
    }

    async fn refresh_dir_list(
        &mut self,
        sftp: &SftpSession,
        cache: &DashMap<fileid3, (fattr3, Instant, String)>,
        id: fileid3,
    ) -> Result<(), nfsstat3> {
        let entry = self
            .id_to_path
            .get(&id)
            .ok_or(nfsstat3::NFS3ERR_NOENT)?
            .clone();

        // if there are children and the metadata did not change
        if entry.children.is_some() && !fattr3_differ(&entry.children_meta, &entry.fsmeta) {
            return Ok(());
        }
        if !matches!(entry.fsmeta.ftype, ftype3::NF3DIR) {
            return Ok(());
        }
        let mut cur_path = entry.name.clone();
        let path = self.sym_to_path(&entry.name);
        let fname = path.to_str().ok_or(nfsstat3::NFS3ERR_IO)?;
        let mut new_children: Vec<u64> = Vec::new();
        debug!("Relisting entry {:?}: {:?}. Ent: {:?}", id, path, entry);
        if let Ok(mut listing) = sftp.read_dir(fname).await {
            while let Some(entry) = listing.next() {
                let osstr: OsString = entry.file_name().into();
                let sym = self.intern.intern(osstr).unwrap();
                cur_path.push(sym);
                let meta = entry.metadata();
                let (next_id, fattr) = self
                    .create_entry(&cur_path, meta)
                    .await
                    .or(Err(nfsstat3::NFS3ERR_IO))?;
                cache.insert(
                    next_id,
                    (
                        fattr,
                        Instant::now(),
                        self.sym_to_path(&cur_path).to_string_lossy().to_string(),
                    ),
                );

                new_children.push(next_id);
                cur_path.pop();
            }
            self.id_to_path
                .get_mut(&id)
                .ok_or(nfsstat3::NFS3ERR_NOENT)?
                .children = Some(BTreeSet::from_iter(new_children.into_iter()));
        }
        Ok(())
    }

    async fn create_entry(
        &mut self,
        fullpath: &Vec<Symbol>,
        meta: Metadata,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let (next_id, metafattr) = if let Some(chid) = self.path_to_id.get(fullpath) {
            let metafattr = metadata_to_fattr3(*chid, &meta).unwrap();
            if let Some(chent) = self.id_to_path.get_mut(chid) {
                chent.fsmeta = metafattr;
            }
            (*chid, metafattr)
        } else {
            // path does not exist
            let next_id = self.next_fileid.fetch_add(1, Ordering::Relaxed);
            let metafattr = metadata_to_fattr3(next_id, &meta).unwrap();
            let new_entry = FSEntry {
                name: fullpath.clone(),
                fsmeta: metafattr,
                children_meta: metafattr,
                children: None,
            };
            self.id_to_path.insert(next_id, new_entry);
            self.path_to_id.insert(fullpath.clone(), next_id);
            (next_id, metafattr)
        };
        Ok((next_id, metafattr))
    }
}

pub struct SshFs {
    sftp: SftpSession,
    fsmap: tokio::sync::Mutex<FSMap>,
    cache: Arc<DashMap<fileid3, (fattr3, Instant, String)>>,
    cache_timeout: u16,
    write_support: bool,
}

impl SshFs {
    pub fn new(
        sftp: SftpSession,
        root: PathBuf,
        cache: Arc<DashMap<fileid3, (fattr3, Instant, String)>>,
        cache_timeout: u16,
        write_support: bool,
    ) -> SshFs {
        SshFs {
            sftp,
            fsmap: tokio::sync::Mutex::new(FSMap::new(root)),
            cache,
            cache_timeout,
            write_support,
        }
    }
}

#[async_trait]
impl NFSFileSystem for SshFs {
    fn root_dir(&self) -> fileid3 {
        0
    }
    fn capabilities(&self) -> VFSCapabilities {
        if self.write_support {
            VFSCapabilities::ReadWrite
        } else {
            VFSCapabilities::ReadOnly
        }
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let mut fsmap = self.fsmap.lock().await;
        if let Ok(id) = fsmap.find_child(dirid, filename) {
            if fsmap.id_to_path.contains_key(&id) {
                return Ok(id);
            }
        }

        // This a bold assumption, but greatly improves osx performance
        // We assume that if a directory has been indexed, and there's no
        // child entries for ._ files, they are pointless lookups
        if let Some(children) = &fsmap
            .id_to_path
            .get(&dirid)
            .ok_or(nfsstat3::NFS3ERR_NOENT)?
            .children
        {
            if !children.is_empty() && filename.starts_with(b"._") {
                return Err(nfsstat3::NFS3ERR_NOENT);
            }
        }

        // Optimize for negative lookups.
        // See if the file actually exists on the filesystem
        let dirent = fsmap.find_entry(dirid)?;
        let mut path = fsmap.sym_to_path(&dirent.name);
        let objectname_osstr = OsStr::from_bytes(filename).to_os_string();
        path.push(&objectname_osstr);
        let fname = path.to_str().ok_or(nfsstat3::NFS3ERR_IO)?;
        if !self
            .sftp
            .try_exists(fname)
            .await
            .or(Err(nfsstat3::NFS3ERR_IO))?
        {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        if let RefreshResult::Delete = fsmap.refresh_entry(&self.sftp, &self.cache, dirid).await? {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        let _ = fsmap.refresh_dir_list(&self.sftp, &self.cache, dirid).await;

        fsmap.find_child(dirid, filename)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        if let Some(kv) = self.cache.get(&id) {
            // If this stat is old, refresh it use it.
            if kv.1.elapsed().as_secs() < self.cache_timeout as u64 {
                return Ok(kv.0);
            }
        }
        let mut fsmap = self.fsmap.lock().await;
        if let RefreshResult::Delete = fsmap.refresh_entry(&self.sftp, &self.cache, id).await? {
            return Err(nfsstat3::NFS3ERR_NOENT);
        }
        let ent = fsmap.find_entry(id)?;

        // Update cache
        self.cache.insert(
            id,
            (
                ent.fsmeta,
                Instant::now(),
                fsmap.sym_to_path(&ent.name).to_string_lossy().to_string(),
            ),
        );
        Ok(ent.fsmeta)
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let cached = self.cache.get(&id);
        let (len, ostr) = if cached.is_none() {
            let fsmap = self.fsmap.lock().await;
            let ent = fsmap.find_entry(id)?;
            let path = fsmap
                .sym_to_path(&ent.name)
                .into_os_string()
                .into_string()
                .or(Err(nfsstat3::NFS3ERR_IO))?;
            let len = ent.fsmeta.size;
            self.cache
                .insert(id, (ent.fsmeta, Instant::now(), path.to_owned()));
            drop(fsmap);
            (len, path)
        } else {
            let c = cached.unwrap();
            (c.0.size, c.2.to_owned())
        };
        let start = offset.min(len);
        let end = (offset + count as u64).min(len);

        let mut file = self.sftp.open(ostr).await.or(Err(nfsstat3::NFS3ERR_IO))?;
        file.seek(SeekFrom::Start(start))
            .await
            .or(Err(nfsstat3::NFS3ERR_IO))?;
        let mut buf = vec![0; (end - start) as usize];
        file.read_exact(&mut buf)
            .await
            .or(Err(nfsstat3::NFS3ERR_IO))?;
        let eof = buf.is_empty();
        Ok((buf, eof))
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let mut fsmap = self.fsmap.lock().await;
        fsmap.refresh_entry(&self.sftp, &self.cache, dirid).await?;
        fsmap
            .refresh_dir_list(&self.sftp, &self.cache, dirid)
            .await?;

        let entry = fsmap.find_entry(dirid)?;
        if !matches!(entry.fsmeta.ftype, ftype3::NF3DIR) {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }

        self.cache.insert(
            dirid,
            (
                entry.fsmeta,
                Instant::now(),
                fsmap.sym_to_path(&entry.name).to_string_lossy().to_string(),
            ),
        );
        let children = entry.children.ok_or(nfsstat3::NFS3ERR_IO)?;

        let mut ret = ReadDirResult {
            entries: Vec::new(),
            end: false,
        };

        let range_start = if start_after > 0 {
            Bound::Excluded(start_after)
        } else {
            Bound::Unbounded
        };

        let remaining_length = children.range((range_start, Bound::Unbounded)).count();

        for i in children.range((range_start, Bound::Unbounded)) {
            let fileid = *i;
            let fileent = fsmap.find_entry(fileid)?;
            let name = fsmap.sym_to_fname(&fileent.name);
            ret.entries.push(DirEntry {
                fileid,
                name: name.as_bytes().into(),
                attr: fileent.fsmeta,
            });
            if ret.entries.len() >= max_entries {
                break;
            }
        }

        if ret.entries.len() == remaining_length {
            ret.end = true;
        }

        Ok(ret)
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let fsmap = self.fsmap.lock().await;
        let ent = fsmap.find_entry(id)?;
        let path = fsmap.sym_to_path(&ent.name);
        drop(fsmap);
        let fname = path.to_str().ok_or(nfsstat3::NFS3ERR_IO)?;
        if let Ok(target) = self.sftp.read_link(fname).await {
            Ok(OsString::from(target).as_os_str().as_bytes().into())
        } else {
            Err(nfsstat3::NFS3ERR_IO)
        }
    }

    #[allow(unused)]
    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    #[allow(unused)]
    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    #[allow(unused)]
    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        setattr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    #[allow(unused)]
    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    #[allow(unused)]
    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    #[allow(unused)]
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        {
            let fsmap = self.fsmap.lock().await;
            let entry = fsmap.id_to_path.get(&dirid).ok_or(nfsstat3::NFS3ERR_IO)?;
            let mut path = fsmap.sym_to_path(&entry.name);
            let name = OsStr::from_bytes(dirname).to_os_string();
            path.push(&name);

            self.sftp
                .create_dir(path.to_string_lossy().to_string())
                .await
                .or(Err(nfsstat3::NFS3ERR_IO))?;
        }

        let id = self
            .lookup(dirid, dirname)
            .await
            .or(Err(nfsstat3::NFS3ERR_NOENT))?;
        let attr = self.getattr(id).await.or(Err(nfsstat3::NFS3ERR_NOENT))?;
        Ok((id, attr))
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
}
