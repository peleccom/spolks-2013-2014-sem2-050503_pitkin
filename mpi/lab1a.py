#!/usr/bin/env python2
from mpi4py import MPI
import numpy as np
import matrix










ARRAY_DIM = 6
ARRAY_SIZE = ARRAY_DIM * ARRAY_DIM
comm = MPI.COMM_WORLD
rank = comm.Get_rank()
size = comm.Get_size()
a = np.arange(ARRAY_SIZE).reshape(ARRAY_DIM, ARRAY_DIM)
b = np.arange(ARRAY_SIZE, 2 * ARRAY_SIZE).reshape(ARRAY_DIM, ARRAY_DIM)
c = np.zeros((ARRAY_DIM, ARRAY_DIM), dtype=np.int32)

start, stop = matrix.get_rank_indexes(rank,size, ARRAY_DIM)
c_elements = matrix.mul_matrix_partial(a, b,start, stop, ARRAY_DIM)
matrix.copy_matrix_slice(c, c_elements, start, stop, ARRAY_DIM)
if rank == 0:
    # main process
    status = MPI.Status()
    for i in range(size-1):
        c_elements = comm.recv(source=MPI.ANY_SOURCE,tag=10, status=status)
        source = status.Get_source()
        start, stop = matrix.get_rank_indexes(source, size, ARRAY_DIM)
        matrix.copy_matrix_slice(c, c_elements, start, stop, ARRAY_DIM)
    print "result matrix\n" ,c
    print "true result\n", np.dot(a,b)

else:
    comm.send(c_elements, dest=0,tag=10)

