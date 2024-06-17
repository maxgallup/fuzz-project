import r2pipe

# Initialize the radare2 pipe
r = r2pipe.open('./binaries/mario')

output = r.cmdj('pdfj')

print(output)

