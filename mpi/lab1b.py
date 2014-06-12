#!/usr/bin/env python2

from mpi4py import MPI
import numpy as np
import matrix
from array import array


ARRAY_DIM = 6
ARRAY_SIZE = ARRAY_DIM * ARRAY_DIM
comm = MPI.COMM_WORLD
rank = comm.Get_rank()
size = comm.Get_size()
a = np.arange(ARRAY_SIZE).reshape(ARRAY_DIM, ARRAY_DIM)
b = np.arange(ARRAY_SIZE, 2 * ARRAY_SIZE).reshape(ARRAY_DIM, ARRAY_DIM)
c = np.zeros((ARRAY_DIM, ARRAY_DIM), dtype=np.int32)


if rank == 0:
    # main process

    c_parts = []
    reqs = []
    for i in range(size-1):
        c_elements = np.empty(ARRAY_SIZE, dtype=np.int32)
        req = comm.Irecv(c_elements ,source=i+1, tag=10)
        reqs.append(req)
        c_parts.append(c_elements)
    start, stop = matrix.get_rank_indexes(rank,size, ARRAY_DIM)
    c_elements = matrix.mul_matrix_partial(a, b, start, stop, ARRAY_DIM)
    matrix.copy_matrix_slice(c, c_elements, start, stop, ARRAY_DIM)
    MPI.Request.Waitall(reqs)
    for i in range(size-1):
        start, stop = matrix.get_rank_indexes(i+1, size, ARRAY_DIM)
        matrix.copy_matrix_slice(c, c_parts[i], start, stop, ARRAY_DIM)

    print "result matrix\n" ,c
    print "true result\n", np.dot(a,b)

else:
    start, stop = matrix.get_rank_indexes(rank,size, ARRAY_DIM)
    c_elements = matrix.mul_matrix_partial(a, b, start, stop, ARRAY_DIM)
    c_elements = np.array(c_elements, dtype=np.int32)
    comm.Isend(c_elements, dest=0,tag=10)

