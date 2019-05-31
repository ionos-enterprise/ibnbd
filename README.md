InfiniBand Transport (IBTRS) & Infiniband Network Block Device (IBNBD)
======================================================================

Short introduction
------------------

IBNBD/IBTRS were created with one aim: provide simple way to map a remote
device on a client machine from a server machine.  IBNBD is nothing more
but a block device which uses IBTRS as a transport library to send I/O
requests.  IBTRS in its turn manages RDMA (InfiniBand, RoCE, iWarp)
connections between client and server.

IBNBD documentation is [here](./ibnbd/README).

IBTRS documentation is [here](./ibtrs/README).

Contact
-------

Mailing list: "IBNBD/IBTRS Storage Team" <ibnbd@cloud.ionos.com>
