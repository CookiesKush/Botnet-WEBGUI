data = str(input("Enter a string: "))

data = data.replace("root ","").split()
str1 = ' '.join(data)
print(str1)