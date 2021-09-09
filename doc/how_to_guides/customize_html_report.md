
# How do I create a custom theme for the HTML Report?

CVE Binary Tool provides HTML Report as an output type and although the Report design will work for most of the users it might be the case that we want to update the Report Design according to our needs. So in this tutorial, we will be discussing on how to customise the HTML Report.

CVE Binary Tool provides the functionality to edit report components which we can use to redesign or change the report. CVE Binary Tool uses Object Oriented Programming approach for redesigning that means we need to overwrite files to update the design. 

> Example: If we want to update the dashboard then we only need to provide `dashboard.html` file. It will update the dashboard design as specified in the given file. All the remaining design will be as it is.

Before we start let's discuss the requirements. So first and the most important requirement is that we must know `Jinja` because cve-bin-tool uses that as its templating engine. We don't need the advance concepts but knowledge of jinja variables `{{ }}` and jinja block `{% %}` is a must. For more info see [Jinja Basics.](https://jinja.palletsprojects.com/en/2.11.x/templates/) Second we must setup a directory to work with. So let's start by creating a new directory. 

> This guide assumes that you are using the version `1.1` or above of `cve-bin-tool`.

## Setting up the directory

Before we start customising the report we have to set up our work directory. Work directory or root directory will contain all the configuration files for components we want to update. 

We first need to set up our root directory and then we need to create config folders inside this root directory.

**steps to setup directory:**

1) Create a root directory anywhere on your computer. We can name this directory whatever we want. I will create a new directory named `my_theme` because I want to store my config files there. 

```console

user@ubuntu: ~$ mkdir my_theme

user@ubuntu: ~$ cd my_theme/

```

2) Create a new config folder `templates`. Config folders are simple folders but with a specified name. Note that the config folder name must match with `templates` otherwise it will not overwrite components.

```console

user@ubuntu: ~/my_theme$ mkdir templates

user@ubuntu: ~/my_theme$ cd templates/

  

# Actual Path After the Steps

user@ubuntu: ~/my_theme/templates$

```

This will set up our templates config folder( templates directory ) and now we are ready to start customising the HTML Report.

## Setting up the Files

Now as we have set up our templates folder we will create files that are needed for the report redesign. CVE Binary Tool allows customisation of 4 basic templates. We only need to implement only those templates that we want to overwrite.

1) base.html

2) dashboard.html

3) row_cve.html

4) row_product.html

These files will control the structure and design of the report. We'll discuss in detail on what things we need to consider while creating these files and we'll also discuss which files correspond to which part of the report. But before that let's create those files.

I'll create those files using terminal but you can also create them with the help any File Manager or Text Editor.

```console

user@ubuntu: ~/my_theme/templates$ touch base.html

user@ubuntu: ~/my_theme/templates$ touch dashboard.html

user@ubuntu: ~/my_theme/templates$ touch row_cve.html

user@ubuntu: ~/my_theme/templates$ touch row_product.html

```

We can confirm that using `ls` in the current directory

```console

user@ubuntu: ~/my_theme/templates$ ls

base.html

dashboard.html

row_cve.html

row_product.html

```

HTML Report with a custom theme can be generated after creating these files and providing the `--html-theme` argument with the root directory path. 

Now we'll discuss in detail to see what is the role of each file and how to customise that according to our needs.

  

### row_cve.html

---------------------

#### Role:

Each CVE has a unique number associated with it called CVE Number and a severity level measuring the level of severity( Critical, High, Medium, Low). Apart from that a small description of CVE is also present. The `row_cve.html` handles all the information about CVE and design. Design info includes component design for a single cve and it must not be a full HTML.
Full html include `<html>, <head> <body>` tags. 

**Example of half html**
```html
<!-- example html file -->
<div>
	<h2> I'm not a full html because I don't have head and body </h2>
	<p> This is a example code for half-html </p>
</div>
```

#### How to customise?

For customising we need to overwrite the `row_cve.html`. We need to provide this file inside the `templates`
directory. We have already created this file inside our templates directory if you are following along. We need to include some jinja variables in `row_cve.html` to include the cve details.

| Jinja Variables | Implementation | Function |
|------------------|----------------|-----------|
| {{ cve_number }} | required | Provides CVE Number |
| {{ severity}} | required | Provides CVE Severity ("CRITICAL", "HIGH", "MEDIUM", "LOW") |
| {{ description }} | required |Provides a small summary of CVE|
| {{ var_id }} | optional | Provides a unique html tag id for each CVE. |

For more help, you can take a look at cve-bin-tool's own `row_cve.html` template implementation.
```html
<!-- CVE Binary Tool's  row_cve.html  -->

<!-- for each cve in CVE list we will have this row-->
<div  class="card listCVE bg-{{ severity }} text-color-main shadow-sm">
	<div  class="row text-left m-t-5 m-b-5">
		<div  class="col-12 col-lg-5 p-t-10 ">
			<h6  class="m-l-10">{{ cve_number }}</h6>
		</div>
		<div  class="col-7 col-lg-4 p-t-10 ">
			<h6  class="m-l-10">Severity: {{ severity }}</h6>
		</div>
		<div  class="col-5 col-lg-3 text-center">
			<button  class="btn borderButton text-color-main"  data-toggle="collapse"  data-target="#info{{ var_id }}">more info</button>
		</div>
	</div>

	<!-- Hidden Data That we want to show -->
	<div  id="info{{ var_id }}"  class="collapse bg-white"  data-parent="#accord{{ fix_id }}">
		<p  class="summary">{{ description }} <a  href="https://nvd.nist.gov/vuln/detail/{{ cve_number}}" target="_blank" rel="noopener noreferrer">..read more</a></p>
	</div>

</div>
```
### row_product.html

---------------------

#### Role:
Each product has one or more CVE associated with it. It also contains information about the Vendor, Version and the name of the Product along with the cve count and a Product Analysis graph based on CVEs. The list of CVEs contains the data rendered with the template `row_cve.html`.

#### How to customise?

For customising we need to overwrite the `row_product.html`. We need to provide this file inside the `templates` directory. We have already created this file inside our templates directory if you are following along. We need to handles the following jinja variables in the `row_product.html`. Again this should not be a full-html. 

| Jinja Variables | Implementation | Function |
|------------------|----------------|-----------|
| {{ vendor }} | required | Vendor name |
| {{ name}} | required | Product name|
| {{ version }} | required | Product version |
| {{ cve_count }} | required | Number of CVEs in product |
| {{ list_cves }} | required | List of CVEs in Product rendered using the `row_cve.html` |
| {{ severity_analysis }} | optional | Pie chart showing the severity level count |
| {{ fix_id }} | optional | Provides a unique html tag id for each Product. |

For more help, you can take a look at cve-bin-tool's own `row_product.html` template implementation.
```html
<!-- CVE Binary Tool's row_product.html -->
<!-- Header for the Product Row [VENDOR, PRODUCT, VERSION, NUMBER_OF_CVES] -->

<div  class="card text-center pHeading text-color-main p-t-5 product">
	<div  class="row">
		<a  class="stretched-link"  data-toggle="collapse" href="#div{{ fix_id }}"></a>
		<!-- Vendor -->
		<div  class="col-6 col-lg">
			<h5  class="font-weight-light">Vendor: {{ vendor }}</h5>
		</div>
		<!-- Product -->
		<div  class="col-6 col-lg">
			<h5  class="font-weight-light">Product: {{ name }}</h5>
		</div>
		<!-- Version -->
		<div  class="col-6 col-lg">
			<h5  class="font-weight-light">Version: {{ version }}</h5>
		</div>
		<!-- Total number of Known vulnerability -->
		<div  class="col-6 col-lg">
			<h5  class="font-weight-light">Number of CVE's: {{ cve_count }}</h5>
		</div>
	</div>
</div>

<!-- Product CVEs start from here -->

<!-- cve row contains ListCVES for each product of specific version and analysis Chart-->
<div  id="div{{ fix_id }}"  class="hideme">
	<div  class="row ">
		<!-- List CVES -->
		<div  class="col-12 col-md-7 col-lg-8"  id="accord{{ fix_id }}">
			{{ list_cves }}
		</div>

		<!-- Analysis Chart for each product version -->
		<div  class="col-12 col-md-5 col-lg-4">
			<div  class="card analysis m-t-10">
				<div  class="card-header text-center bg-header-dash">
					<h6>Severity Analysis of {{ name }} {{ version }}</h6>
				</div>
				<div  class="card-body">
					{{ severity_analysis }}
				</div>
			</div>
		</div>
	</div>
</div>
```
### dashboard.html

---------------------

#### Role:
The dashboard is the main showcase area with two graphs. One with the details of the number of products that were found and the other contains the information about the number of CVEs in the products that were found. 

#### How to customise?

The `dashboard.html` is to be present in our work directory under the templates folder. It must not be a full-html and must handle the following jinja variable.

| Jinja Variables | Implementation | Function |
|------------------|----------------|-----------|
| {{ graph_products }} | required | Pie Chart with data of Products Vulnerable and with no known vulnerability  |
| {{ graph_cves}} | required | Bar Graph to show CVE count in each product and version |
| {{ total_files }} | optional | Total Number of Files that were scanned |
| {{ products_with_cve }} | optional | No of products that were found in the scan |

For more help, you can take a look at cve-bin-tool's own `dashboard.html` template implementation.
```html
<!-- CVE Binary Tool's dashboard.html-->

<!-- Main Information Dashboard -->
<div  class="row m-b-20">
	<!-- Left Col -->
	<div  class="col-12 col-md-4">
	<!-- left-card / Card to show total scanned files and vulnerable products -->
		<div  class="card text-color-main shadow-lg bg-white rounded">
			<!-- Card Header -->
			<div  class="card-header text-color-main text-center bg-header-dash">
				<div  class="row justify-content-sm-centre">
					<div  class="col-6">
						<h6>Scanned Files: {{ total_files }}</h6>
					</div>
					<div  class="col-6">
						<h6>Found {{ products_with_cve }} Products</h6>
					</div>
				</div>
			</div>
			<!-- Card Body -->
			<div  class="card-body">
			<!-- SVG Graph That display total packages with known vulnerability -->
				{{ graph_products }}
			</div>
		</div>
	</div>
	<!-- Right Col -->
	<div  class="col-12 col-md-8">
		<!-- Graph to show Total CVE's in each product -->
		<div  class="card text-color-main shadow-lg bg-white rounded">
			<div  class="card-header bg-header-dash">
				<h6>Product CVES's</h6>
			</div>
			<div  class="card-body">
				{{ graph_cves }}
			</div>
		</div>
	</div>
</div>
```
### base.html

---------------------

#### Role:

As the name suggests `base.html` is the actual base for all other templates and the rendered results of each template are included in this base template. It also holds all the scripts and CSS files and is required to be a full-html. 

#### How to customise?

As such, there is no restriction on how to customise `base.html` but we need to handle some jinja variables otherwise it will not render properly. Also, we must make sure that `plotly.js` is included at the top otherwise the graphs will not render. 

Here is the list of jinja variables that we need to provide in the template.

| Jinja Variables | Implementation | Function |
|------------------|----------------|-----------|
| {{ script_plotly}} | required | JavaScript File for Plotly.js which is needed for Graph Generation |
|{{ dashboard }} | required| This will contain the `dashboard.html` in rendered form |
|{{products_found}}| required | This will have all the products that are found during the scan and rendered in `product_cve.html`
|{{script_jquery}}| required | JQuery.js file |
|{{script_bootstrap}}| required | Bootstrap.js file |
| {{ style_bootstrap}} | required | bootstrap CSS file |
| {{ date }} | optional | date of report generation |
| {{ style_main }} | optional | Your own CSS implementation|
| {{ script_main }} | optional | Your own JavaScript implementation|

For more help, you can take a look at cve-bin-tool's own `base.html` template implementation.
```html

<!DOCTYPE  html>

<html  lang="en">
<head>
	<meta  charset="UTF-8">
	<meta  name="viewport"
		content="width=device-width, initial-scale=1.0, user-scalable=0,shrink-to-fit=no, maximum-scale=1, minimum-scale=1">
	<title>CVE-BIN-TOOL | Descriptive Report</title>

	<!-- JavaScript for Plotly -->
	<script> {{ script_plotly }}</script>
	<!-- Bootstrap CSS -->
	<style>
		/* Bootstrap */
		{{ style_bootstrap }}
		/* Mystylesheet */
		{{ style_main }}
	</style>
</head>
<body>
	<div  class="container-fluid">
	<!-- Name of the tool and Date at which is generated -->
		<div  class="card bg-title text-light m-t-20 m-b-20">
			<div  class="card-header">
				<div  class="row justify-content-sm-centre ">
					<!-- Name of the Tool -->
					<div  class="col-sm-auto col-sm ">
						<h4  class="font-weight-light">CVE Binary Tool: Descriptive Report</h4>
					</div>
					<!-- Report generation date -->
					<div  class="col-sm">
						<h4  class="text-right font-weight-light"> {{ date }}</h4>
					</div>
				</div>
			</div>
		</div>
		<!-- Block for Dashboard -->
		{{ dashboard }}

		<!-- Header All Products -->
		<div  class="card bg-title text-light m-t-20 m-b-15">
			<div  class="card-header">
				<div  class="row">
					<div  class="col-9">
						<h5  class="font-weight-light p-t-5">Products With Known Vulnerability</h5>
					</div>
					<div  class="col-3 text-right">
						<button  class="btn btn-filter borderButton text-color-main"  data-toggle="collapse" data-target="#filterdiv">Search Data</button>
					</div>
				</div>
			</div>
		</div>
		<div  class="row collapse text-center"  id="filterdiv">
			<div  class="offset-4 col-4 onset-4">
				<div  class="active-pink-4 mb-4">
					<input  id="searchInput"  class="form-control"  type="text"  placeholder="Search"  aria-label="Search">
				</div>
			</div>
		</div>
		<!-- List of all the products -->
		<div  id="listProducts">
			{{ products_found }}
		</div>
	</div>
	<!-- Jquery -->
	<script>{{ script_jquery }}</script>
	<!-- Bootstrap JS -->
	<script>{{ script_bootstrap }}</script>
	<script>
		{{ script_main }}
	</script>
</body>
</html>
```

## Adding and updating custom CSS and JavaScript files

CVE Binary Tool uses the bootstrap 4 to style the templates but we might want to use the latest bootstrap version available( bootstrap 5 is in its early stage at the time when I'm writing this tutorial ). It might also be the case that we want to include our custom CSS files and even js files. 

### Updating CSS and JS files
CVE Binary Tool allows us to update the CSS and JS files in the same manner as we update the templates. So we just need to create a new config folder inside our work directory(In our case `my_theme`) named  `css` to update the CSS files and other named `js` to update the javascript files. 

Here is the list of files that we can update.

#### CSS FILES
|File name | Functionality | 
|----------|---------------|
|bootstrap.css| Bootstrap.css file for the report |
|main.css| Custom CSS file for the report |

> Example: If we want to update the `main.css` file we'll create a `main.css` file inside the `css` folder under the work directory(`my_theme`).  

#### JavaScript FILES
|File name | Functionality | 
|----------|---------------|
|bootstrap.js| Bootstrap.js file for the report |
|plotly.js| Plotly.js is used for graph generation |
|jquery.js| JQuery file for the report |
|main.js| Custom JavaScript for the report |

> Example: If we want to update the `main.js` file we'll create a `main.js` file inside the `js` folder under the work directory(`my_theme`).  

### Adding CSS and JavaScript
Apart from the given files, we might want to include other Popular JS and CSS files like we might want to add `Font Awesome`, `Popper.js` or any other custom CSS or js file. 

So to add custom styles we need to include them in the `base.html` inside the templates directory. So the implementation of `base.html` is a must. If we don't want to update the cve-bin-tool's  `base.html` then we can copy the template and paste that in the templates folder of our work directory and then
we can include our CSS and js files.

There are two methods to include CSS and js
1) Use CDNs to include js and CSS files
2) Copy the contents of CSS and JS files directly inside the `base.html`. This method is recommended as it will allow the report to work even in complete offline mode(No Internet). 

We know that we must maintain different HTML, CSS and js files but because we want to generate a single report file so need to include everything in a single file.   


> For more help or suggestion you can contact our
> [community](https://gitter.im/cve-bin-tool/community).
