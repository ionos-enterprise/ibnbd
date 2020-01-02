RDMA Transport (RTRS) & RDMA Network Block Device (RNBD)
======================================================================

Short introduction
------------------

RNBD/RTRS were created with one aim: provide simple way to map a remote
device on a client machine from a server machine.  RNBD is nothing more
but a block device which uses RTRS as a transport library to send I/O
requests.  RTRS in its turn manages RDMA (InfiniBand, RoCE, iWarp)
connections between client and server.

RNBD documentation is [here](./rnbd/README).

RTRS documentation is [here](./rtrs/README).
