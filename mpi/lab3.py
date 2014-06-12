from mpi4py import MPI
import numpy as np
import sys
from argparse import ArgumentParser
import time
from StringIO import StringIO
import pickle
import matrix



parser = ArgumentParser()
parser.add_argument("-g","--groups", type=int, required=True, help="groups count")
parser.add_argument("first_matrix", nargs="?",
            help="first matrix file path",)
parser.add_argument("second_matrix", nargs="?",
            help="second matrix file path")
args = parser.parse_args()

aname = args.first_matrix
bname = args.second_matrix

comm = MPI.COMM_WORLD
group = comm.Get_group()

afile = MPI.File.Open(comm, aname, amode=MPI.MODE_RDONLY)
bfile = MPI.File.Open(comm, bname, amode=MPI.MODE_RDONLY)

abuf = bytearray(afile.Get_size())
bbuf = bytearray(bfile.Get_size())

afile.Read_all(abuf)
bfile.Read_all(bbuf)

a = pickle.loads(abuf)
b = pickle.loads(bbuf)

afile.Close()
bfile.Close()


num_rows,num_columns = a.shape

if (num_columns, num_rows) != b.shape:
    print "matrix shapes don't match"
    sys.exit(1)

c = np.zeros((num_rows,num_columns), dtype=np.int32)

groups = list(np.array_split(range(comm.size), args.groups))
dist = {}

for gid, ranks in enumerate(groups):
    sgroup = MPI.Group.Incl(group, ranks)
    dist.update({rank: (gid, sgroup) for rank in ranks})

gid, sgroup = dist[comm.rank]
scomm = comm.Create(sgroup)


cname = "out/group-%d.matrix" % gid

try:
    MPI.File.Delete(cname)
except MPI.Exception:
    pass

cfile = MPI.File.Open(scomm, cname, MPI.MODE_WRONLY + MPI.MODE_CREATE)

start = time.time()

indexes = np.array_split(range(num_columns * num_rows), scomm.size)
indexes = scomm.scatter(indexes)

c_elements = matrix.mul_matrix_partial(a,b,indexes[0], indexes[-1] + 1, num_columns)
#
computations = StringIO()

index = indexes[0]
for element in c_elements:
    if (index) and ((index % num_columns) == 0):
        computations.write("\n")
    computations.write("%s " % element)
    index += 1
s = computations.getvalue()
cfile.Write_ordered(s)
ans = scomm.gather(c_elements)

if scomm.rank == 0:
    i = 0
    for elements in ans:
        matrix.copy_matrix_slice(c, elements, i, i + len(elements), num_columns)
        i += len(elements)
scomm.barrier()

end = time.time()
cfile.Close()

times = scomm.allgather(end-start)
print("Global rank: %s, Group: %s, Rank in group: %s, Group Size: %s, time: %s" %
            (comm.rank, gid, scomm.rank, scomm.size, max(times)))

if scomm.rank == 0:
    print c


