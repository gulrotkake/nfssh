# nfssh - NFS+SSH - Mount remote FS over SSH as NFS

Fair warning - this is a prototype.

This is a weekend hack to combine [russh](https://github.com/warp-tech/russh) with [nfsserve](https://github.com/xetdata/nfsserve) in order to mount a remote filesystem on a mac without the need for kernel extensions (kext). For now it is only read-only.
