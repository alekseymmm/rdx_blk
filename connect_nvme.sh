#~/usr/bin/bash
nvme discover -q nqn.raidix12_1 -t rdma -a 10.30.0.12 -s 4420
sleep 2
nvme discover -q nqn.raidix12_2 -t rdma -a 10.20.0.12 -s 4421
sleep 2
nvme connect -t rdma -n nqn.raidix12_1 -a 10.30.0.12 -s 4420
sleep 2
nvme connect -t rdma -n nqn.raidix12_2 -a 10.20.0.12 -s 4421
sleep 2
nvme discover -q nqn.raidix3_1 -t rdma -a 10.30.0.3 -s 4420
sleep 2
nvme discover -q nqn.raidix3_2 -t rdma -a 10.20.0.3 -s 4421
sleep 2
nvme connect -t rdma -n nqn.raidix3_1 -a 10.30.0.3 -s 4420
sleep 2
nvme connect -t rdma -n nqn.raidix3_2 -a 10.20.0.3 -s 4421
