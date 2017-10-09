#~/usr/bin/bash
nvme discover -t rdma -a 10.30.0.16 -s 4420
nvme discover -t rdma -a 10.20.0.16 -s 4421
nvme connect -t rdma -n nqn.raidix16_1 -a 10.30.0.16 -s 4420
nvme connect -t rdma -n nqn.raidix16_2 -a 10.20.0.16 -s 4421
