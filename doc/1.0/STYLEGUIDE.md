# Style Guide for cve-bin-tool
This list contains all the style guide that one must follow while contributing so that code is consistent and maintaiable.

## String Formatting
Python provide many different ways to format the string(you can read about them [here](https://realpython.com/python-formatted-output/))and we use f-string formatting in our tool.

**Note: As f-strings are only supported in python 3.6+. Please make sure you have version >=3.6** 

- **Example:** Formatting string using f-string
```python
#Program prints a string containing name and age of person
name = "John Doe"
age = 23
print(f"Name of the person is {name} and his age is {age}")

#Output
# "Name of the person is John Doe and his age is 23"
```
Note that the string started with the **'f'** followed by the string. Values are always added in the curly braces. Also we don't need to convert age into string. (we may have used **str(age )** before using it in the string) f-strings are useful as they provide many cool features. You can read more about features and the good practices to use f-strings [here](https://realpython.com/python-f-strings/#f-strings-a-new-and-improved-way-to-format-strings-in-python).

## Style Format
CVE Binary Tool uses Black as the style formatter. Contributors are requested to format their code with Black before submitting.

###  Installing Black
Black can be easily installed with the help of pip. 
```bash
$ pip install black
```  

### Formatting Code
Formatting a file is easy. Just navigate to the file and run the following command. For formatting a particular file name filename.py.
```bash
$ black filename.py
```
But in real life you might want to format each file in a particular folder. 
```bash
$ cd Code/
$ black ./
```
In my case the name of the folder is Code. First navigate to the folder and then use black on the folder using  ```./``` 

