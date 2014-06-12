#!/usr/bin/env python

from argparse import ArgumentParser
import numpy as np
import pickle


parser = ArgumentParser()
parser.add_argument("-r", "--rows", type=int, required=True,
        help="specify rows count")
parser.add_argument("-c", "--columns", type=int, required=True,
        help="specify columns count")
parser.add_argument("-s", "--start", type=int, required=False,
        help="start index", default = 0)
args = parser.parse_args()
rows = args.rows
cols = args.columns
start = args.start
a = np.arange(start + rows * cols).reshape(rows, cols)
b = np.arange(start + rows * cols, 2 * rows * cols).reshape(rows, cols)

with open("a.m", "w+") as file:
    pickle.dump(a, file)

with open("b.m", "w+") as file:
    pickle.dump(b, file)

