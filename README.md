# nfssh - NFS+SSH - Mount remote FS over SSH as NFS

Fair warning - this is a prototype.

This is a weekend hack to combine [russh](https://github.com/warp-tech/russh) with [nfsserve](https://github.com/xetdata/nfsserve) in order to mount a remote filesystem on a mac without the need for kernel extensions (kext). For now it mounts as a read-only filesystem.

## Usage

```
$ cargo run -- --host <hostname> [--username <username>] [--password <password>] [--port <port>] [--directory <directory>]
```

This starts an NFS server on port 11111. This can be mounted using:

```
mount_nfs -o nolocks,vers=3,tcp,rsize=131072,actimeo=120,port=11111,mountport=11111 localhost:/ <target>
```
