import time


def time_it(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Function {func.__name__} took {end_time - start_time:.4f} seconds to execute")
        return result
    return wrapper


@time_it
def slow_function(seconds):
    print(f"Sleeping for {seconds} seconds...")
    time.sleep(seconds)
    return "Finished"


res = slow_function(3)
print(res)

if __name__ == "__main__":
    pass
