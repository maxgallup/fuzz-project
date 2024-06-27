import os

files = list(map(lambda x: os.path.join("./input_dir", x), os.listdir("./input_dir")))
for filename in files:
    with open(filename, "rb") as f:
        content = f.read()
    with open(filename, "wb") as f:
        # f.write(content[:100])
        # f.write(content[102:len(content)//2])
        f.write(content[:100])

