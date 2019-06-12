#include <Python.h>
#include <ctype.h>

static PyObject* pstringLib_string(PyObject* self, PyObject* args) {

    // Read the argument passed from Python
    char *path;
    if (!PyArg_ParseTuple(args, "s", &path)) {
        return NULL;
    }

    // Read binary file
    char *buffer;
    FILE *fptr;
    unsigned long fileLen;

    if ((fptr = fopen(path, "rb")) == NULL)
    {
        fprintf(stderr, "Error! opening file");
        // Program exits if file pointer returns NULL.
        exit(1);         
    }

	fseek(fptr, 0, SEEK_END);
	fileLen=ftell(fptr);
	fseek(fptr, 0, SEEK_SET);

	//Allocate memory
	buffer=(char *)malloc(fileLen+1);
	if (!buffer)
	{
		fprintf(stderr, "Memory error!");
                                fclose(fptr);
		return NULL;
	}

	//Read file contents into buffer
	unsigned long result = fread(buffer, 1, fileLen, fptr);

    fclose(fptr); 

    /*
    for (unsigned long i = 0; i < result; i++) {
        if (buffer[i] > 31 && buffer[i] < 128)
            printf("%c", buffer[i]);
    }
    */

    char *str = malloc(2);
    str[0] = buffer[0];
    str[1] = '\0';

    char *old = str;
    char *new;
    unsigned long i;
    for (i = 1; i < result; i++) {

        size_t len = strlen(old);
        new = malloc(len + 1 + 1); /* one for extra char, one for trailing zero */
        strcpy(new, old);
        free(old);

        // if printable (not sure why isprint is not working)
        if (buffer[i] > 31 && buffer[i] < 128) {
            new[len] = buffer[i];
            new[len + 1] = '\0';
        }
        else {
            // checks whether there are two continous '\n'
            if (new[len - 1] != '\n') {
                // checks whether the character before is a single (useless) character
                if (len - 3 >= 0) {
                    if (new[len - 3] == '\n')
                        new[len - 2] = '\0';
                    else {
                        new[len] = '\n';
                        new[len + 1] = '\0';
                    }
                }
            }
            else
                new[len] = '\0';
        }
        old = new;
    }
    //printf("%s\n", new);

    free(buffer);
    return Py_BuildValue("s", new);
};

// module's function table
static PyMethodDef pstringLib_FunctionsTable[] = {  
    {
        "string", // name exposed to Python
        pstringLib_string, // C wrapper function
        METH_VARARGS, // received variable args (but really just 1)
        "Read file" // documentation
    }, {
        NULL, NULL, 0, NULL
    }
};

// modules definition
static struct PyModuleDef pstring = {  
    PyModuleDef_HEAD_INIT,
    "pstring",     // name of module exposed to Python
    "Python wrapper for string C extension library.", // module documentation
    -1,
    pstringLib_FunctionsTable
};

PyMODINIT_FUNC PyInit_pstring(void) {  
    return PyModule_Create(&pstring);
}
