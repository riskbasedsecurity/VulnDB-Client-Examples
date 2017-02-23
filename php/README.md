# VulnDB PHP API #

Code for client side VulnDB PHP applications.

## VulnDB PHP API Syntax & Usage ##

VulnDB is an extensive database of computer vulnerabilities collected from many different verified and trusted sources. This API wrapper is designed to make integration of your RBS VulnDB account to any PHP project very simple and painless.

## Whats needed? ##

1. PHP5 compiled with OAuth and cURL.
2. Risk Based Security VulnDB OAuth API Keys [here](https://vulndb.cyberriskanalytics.com/oauth_clients)
3. Read API Documentation to understand its usage [here](https://vulndb.cyberriskanalytics.com/documentation/api) and [here](https://vulndb.cyberriskanalytics.com/doc/classes/Api/V1/ApiController.html)

### Notes ###

1. Urged to use intval(integer) for size, page & id arguments.
2. Only one API call will be carried out per class call.
3. Key by_id is not a valid API call but is needed to define vendor display by vendor ID with PHP API. 
4. You will need to use urlencode if a string value has any special chars or spaces.
5. Full list of howtos and usage examples [here](https://vulndb.cyberriskanalytics.com/documentation/howtos)

## Examples  ##

### Config of API ###

VulnDB.class.php has a few options within it for the API keys.
Locate these on line 17 and 21 and add your API key that can be obtained from [here](https://vulndb.cyberriskanalytics.com/oauth_clients)

```php

/**
 * oAuth Key
 **/	
var $oauth_key = '';
/**
 * CoAuth Secret
 **/	
var $oauth_secret = '';

````

There is also a few other options in the class file that can be adjusted. 

Strongly Advise that $debug is set to false in production enviroments and $nice_not_found_406 should be set as true in production

```php

/**
 * create a nice 406 notice
 **/	
var $nice_not_found_406 = true;
/**
 * ignore not found 406
 **/	
var $not_found_406 = false;
/**
 * debug
 **/	
var $debug = false;
	
```

### Complete Usage examples below. ###

Include file to your project as below, besure to keep the OAuth.php file in the same directory as VulnDB.class.php.

```php
include ('VulnDB.class.php');
```
			
#### Vendors examples ####

```php

$arguments_vendor = array(

	 # Returns vendors ordered by name, defaults to 20 vendors per page.
	// '', //submit empty array for list
	
	 # Search vendors by name and may return up to 5 results.
	//'by_name?vendor_name' => 'wordpress', 
	
	 # Returns all the vendors associated with a given product id.
	//'by_product_id?product_id' => 23232, 
	
	 # Returns vendor by id. Http status code 404 will be returned if no vendor matches the vendor_id.
	 'by_id' => intval(228098),  
	 
	 # Returns all the newly created vendors within a date range. Set the start_date parameter to be 2015-12-1 or later to receive the most accurate results.
	//'new_vendors?start_date' => '2015-12-1','end_date'=>'2016-12-1', 
	  
);

$vuln = new VulnDB('vendors', $arguments_vendor);
echo $vuln->_json;
```	
#### Products examples  ####
 
```php
$arguments_product = array(
	
	# Returns 20 products ordered by name.
	// '', //submit empty array for list
	
	# Returns 20 products by vendor name.
	//'by_vendor_name?vendor_name' => 'wordpress',
   
	# Returns 20 products by vendor id.
	//'by_vendor_id?vendor_id' => intval(228098),
	
	# Search a vendors products by name and may return up to 5 results.
	//'by_vendor_id_and_product_name?vendor_id' => intval(228098), 'vendor_name' => urlencode('wordpress'),
	
	# Returns product by ID
	//'by_id' => intval(95540),  
	
	# Returns all the newly created products within a date range. Set the start_date parameter to be 2015-12-1 or later to receive the most accurate results
	//'new_products?start_date' => '2015-12-1',  'end_date'=> '2016-12-1',
	
);

$vuln = new VulnDB('products', $arguments_product);
echo $vuln->_json;
```
#### Versions examples  ####

```php
$arguments_versions = array(
					
	# Returns versions by product name.
   //'by_product_name?product_name' => 'wordpress', 'size' => intval(5), 'page' => intval(1), 'affected' => true
	
	# Returns versions by product id.
	//'by_product_id?product_id' => intval(228098), 'size' => intval(5), 'page' => intval(1), 'affected' => true
		
);
					
$vuln = new VulnDB('versions', $arguments_versions);
echo $vuln->_json;
```

#### Classifications examples ####

```php

// category  = optional
$arguments_classifications = array(
	// submit empty array for list
	# Returns 20 classifications ordered by name.
   '?size' => intval(5), 'page' => intval(1), 'category' => intval(1),
	);
$vuln = new VulnDB('classifications', $arguments_classifications);
echo $vuln->_json;

```

#### Vulnerabilites examples ####

```php

 // General options
 //  nested: When set to true the returned list of products/versions is nested within the affected vendors list, defaults to false.
 // 'nested'=>true
 //  additional_info: When set to true additional information from nvd related to the vulnerability is returned with each vulnerability, defaults to false.
 // 'additional_info' => true 
$arguments_vulnerabilities = array(
	  
	  # Returns the 20 most recent vulnerabilities.
	 // submit empty array for list
	  
	  # Returns a specific VulnDB ID or status 406 Not Acceptable if not found.
	 //'osvdb_id' => intval(95540),
	  
	  # Returns an VulnDB ID based on the associated Bugtraq ID (BID) or status 406 Not Acceptable if not found.
	 //'by_id' => intval(3769), 'find_by_bugtraq_id' => '',
	  
	  # Returns an VulnDB ID based on the associated CERT VU ID or status 406 Not Acceptable if not found.
	 //'by_id' => intval(229804), 'find_by_certvu_id' => '',
	  
	  # Returns an VulnDB ID based on the associated CVE ID or status 406 Not Acceptable if not found.
	 //'by_id' => '2014-1232', 'find_by_cve_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Exploit-DB ID (EBD-ID) or status 406 Not Acceptable if not found.
	 //'by_id' => intval(3906), 'find_by_exploitdb_id' => '',
	  
	  # Returns an VulnDB ID based on the associated ISS X-Force ID or status 406 Not Acceptable if not found.
	 //'by_id' => intval(58835), 'find_by_iss_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Milworm ID or status 406 Not Acceptable if not found. Note: The Milworm site has gone offline and data migrated to Exploit-DB
	 //'by_id' => intval(1106), 'find_by_milworm_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Microsoft Security Bulletin (e.g., MS12-001) or status 406 Not Acceptable if not found.
	 //'by_id' => 'MS12-001', 'find_by_mssb_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Tenable Nessus Plugin ID or status 406 Not Acceptable if not found.
	 //'by_id' => '10001', 'find_by_nessus_id' => '',
	  
	  # Returns an VulnDB ID based on the associated OVAL ID or status 406 Not Acceptable if not found.
	 //'by_id' => '7711', 'find_by_oval_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Secunia ID or status 406 Not Acceptable if not found.
	 //'by_id' => '55286', 'find_by_secunia_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Snort ID or status 406 Not Acceptable if not found.
	 //'by_id' => intval(10001), 'find_by_snort_id' => '',
	  
	  # Returns an VulnDB ID based on the associated Security Tracker ID or status 406 Not Acceptable if not found.
	 //'by_id' => intval(1028915), 'find_by_st_id' => '',
	  
	  # Returns VulnDB IDs starting from start date or within date range
	 //'find_by_date?start_date' => date('y-m-d'), 'end_date' => date('y-m-d'), 'date_type' => 'yea',
	  
	  # Returns VulnDB IDs related to a vendor / product by name
	 //'find_by_vendor_and_product_name?vendor_name' => '228098', 'product_name' => 'wordpress',
	  
	  # Returns VulnDB IDs related to a vendor / product by id
	 //'find_by_vendor_and_product_id?vendor_id' => intval(0), 'product_id' => intval(0),
	  
	  # Returns the vulnerabilities related to a product id and version id
	 //'find_by_product_id_and_version_id?product_id' => 1, 'version_id' => 1, 'page' => 1, 'size' => 20,
		  
	  # Returns the vulnerabilities that were updated in the last specified number of hours
	 //'find_by_time?page' => 1, 'size' => 20, 'hours_ago' => 1,			   
	  
	  # Returns the vulnerabilities by CPE
	 //'find_by_cpe?page' => 1, 'size' => 20, 'cpe' => 'value',
	  
	  # Returns all Vulnerabilities that have Metasploit references
	 //'find_all_metasploit?page' => 1, 'size' => 20,
	 
	  # Returns vulnerabilities added after a specific VulnDB id
	 //'?size' => intval(5), 'page' => intval(1),'by_id' => intval(1), 'find_next_osvdb_id' => '', 
	  
	  # Returns vulnerabilities with specific classification id
	 //'by_id' => intval(55), 'find_by_classification_id' => '',
	  
	  # Returns vulnerabilities with multiple classifications ids
	 //'find_by_classifications_ids?classifications_ids' => intval(2).','.intval(29).','.intval(35).','.intval(41).','.intval(38), 'size' => intval(5), 'page' => intval(1)
	  
	  # Returns vulnerabilities by the parameters specified in the query. if a parameter is not specified, all is assumed. 
	 //'q?classifications_ids' => intval(2).','.intval(17).','.intval(21), 'start_date' =>  '2013-1-1', 'end_date' => '2013-1-1', 'date_type' => 'solution_date',
	  );
	// note that array keys page and size can be used as well where not noted.
$vuln = new VulnDB('vulnerabilities', $arguments_vulnerabilities);
echo $vuln->_json;

```

### Examples of calls ###

#### Example 1  ####

Making a call to get a vendor by ID (wordpress in this case):

```php

    $arguments_vendor = array('by_id' => intval(228098),);
    $vuln = new VulnDB('vendors', $arguments_vendor, 'object');
	
```

Return a PHP object that can be used easy in the PHP foreach() function or many other methods, which ever suits your needs.

```php

print_r($vuln->_object);

```

You can also return it as a formatted JSON string which is great for storage.

```php

echo $vuln->_json;

```

#### Example 1 Usage out put of a vendor ID from object ####

Return data as a object. 

```php

echo $vuln->_object->vendor->id;

returns 228098 

```
