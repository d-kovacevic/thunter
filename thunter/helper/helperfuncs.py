"""
Module contains helper functions used in parent modules
"""
import time


def timeit(method):
    """
    Function that will calculate a time of execution of a specific method
    :param method: function that will measured
    :return:
    """
    def timed(*args, **kwargs):
        ts = time.time()
        print("Execution of function {0}(...) has started.".format(method.__name__))
        result = method(*args, **kwargs)
        te = time.time()
        print("Execution of function {0}(...) is complete (execution time is {1:.0f} seconds).".format(method.__name__, te - ts))
        return result
    return timed


def print_table(message, delimiter):
    """
    Print a message surrounded with a delimiter
    :param message:
    :param delimiter:
    :return:
    """
    print((len(message) + 4) * delimiter)
    print("| " + message + " |")
    print((len(message) + 4) * delimiter)