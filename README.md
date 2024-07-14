# nfssh - NFS+SSH - Mount remote FS over SSH as NFS

Fair warning - this is a prototype. Expect bugs :)

This is a weekend hack to combine [russh](https://github.com/warp-tech/russh) with [nfsserve](https://github.com/xetdata/nfsserve) in order to mount a remote filesystem on a mac without the need for kernel extensions (kext). For now it mounts as a read-only filesystem.

## Usage

Start the NFS+SSH server:
```
$ cargo run -- username@example.com:/path
```

This starts an NFS+SSH server on the default port of `11111`. This can be mounted to `<target>` with:
```
mount_nfs -o nolocks,vers=3,tcp,rsize=131072,actimeo=120,port=11111,mountport=11111 localhost:/ <target>
```

### Available options for the NFS+SSH server

```
Options:
  -c, --cache-refresh <CACHE_REFRESH>  [default: 5]
      --cache-expunge <CACHE_EXPUNGE>  [default: 180]
  -p, --port <PORT>                    [default: 22]
  -n, --nfs-port <NFS_PORT>            [default: 11111]
      --log-level <LOG_LEVEL>
  -h, --help                           Print help
  -V, --version                        Print version
```
