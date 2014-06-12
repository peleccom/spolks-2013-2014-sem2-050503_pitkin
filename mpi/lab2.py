from mpi4py import MPI
import numpy as np
import sys
from argparse import ArgumentParser
import time
import matrix



ARRAY_DIM = 6
ARRAY_SIZE = ARRAY_DIM * ARRAY_DIM

comm = MPI.COMM_WORLD
rank = comm.Get_rank()
size = comm.Get_size()

a = np.arange(ARRAY_SIZE).reshape(ARRAY_DIM, ARRAY_DIM)
b = np.arange(ARRAY_SIZE, 2 * ARRAY_SIZE).reshape(ARRAY_DIM, ARRAY_DIM)
c = np.zeros((ARRAY_DIM, ARRAY_DIM), dtype=np.int32)

parser = ArgumentParser(description="groups")
parser.add_argument("-g","--groups", type=int, required=True, help="groups count")
args = parser.parse_args()
groups = list(np.array_split(range(size),  args.groups))
dist =  {}

for gid, ranks in enumerate(groups):
    sgroup = MPI.Group.Incl(comm.Get_group(), ranks)
    dist.update({rank: (gid, sgroup) for rank in ranks})


gid, sgroup = dist[comm.rank]
scomm = comm.Create(sgroup)

start  = time.time()

indexes = np.array_split(range(ARRAY_DIM * ARRAY_DIM), scomm.size)
indexes = scomm.scatter(indexes)
c_elements = matrix.mul_matrix_partial(a,b,indexes[0], indexes[-1] + 1, ARRAY_DIM)
ans = scomm.gather(c_elements)
if scomm.rank == 0:
    i = 0
    for elements in ans:
        matrix.copy_matrix_slice(c, elements, i, i + len(elements), ARRAY_DIM)
        i += len(elements)
scomm.barrier()
end = time.time()
times = scomm.allgather(end-start)

print "Group %s, Global rank %s, Rank in group %s, Group Size: %s, time: %s" %(gid ,rank, scomm.rank, scomm.size, max(times))
comm.barrier()
if scomm.rank == 0:
    print c





