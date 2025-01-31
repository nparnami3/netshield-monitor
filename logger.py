def log_to_file(data, filename="traffic_log.txt"):
    with open(filename, "a") as file:
        file.write(data + "\n")