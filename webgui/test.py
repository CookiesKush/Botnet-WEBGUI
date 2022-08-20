file = input("File path -> ")
l = []
with open(file, "r") as f:
    print("Reading file...")
    l = f.read().split("\n")
f.close()

print("Removing dupes...")
l = list(dict.fromkeys(l))

with open(file + ".clean", "w+") as out:
    for i in l:
        out.write(i + "\n")
out.close()

print("Removed dupes!")
print("Cleaned file was saved -> " + file + ".clean")

