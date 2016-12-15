libcalc.so: lib_calc.o
	gcc -o libcalc.so lib_calc.c lib_calc.h  -fPIC -shared

TestDlopen: TestDlopen.c
	gcc -o TestDlopen TestDlopen.c -ldl

clean:
	rm -rf *.so *.o  *.gch TestDlopen
