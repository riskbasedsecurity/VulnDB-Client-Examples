<?php
/** 
 * @package VulnDB PHP API Wrapper
 * @class VulnDB
 * @desc example for usage of php api wrapper for vulndb
 * @version 1
 * @apiVersion 1
 **/
include ('VulnDB.class.php');

/**
 * Vendors examples
 **/
 // General options
 // 'page' => 1
 // 'size' => 20		 		 
$arguments_vendor = array(
				  
					# Returns 20 products ordered by name.
					 '', //submit empty array for list
					
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

//$vuln = new VulnDB('vendors', $arguments_vendor);
//echo $vuln->_json;


/**
 * Products examples
 **/
 // General options
 // 'page' => 1
 // 'size' => 20		 		 
$arguments_product = array(
					# Returns 20 products ordered by name.
					'', // submit empty array for list
					
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

//$vuln = new VulnDB('products', $arguments_product);
//echo $vuln->_json;

/**
 * Versions examples
 **/
 // General options
 // 'page' => 1
 // 'size' => 20		 		 
 // 'affected' => true		 		 
$arguments_versions = array(
					
					# Returns versions by product name.
				   //'by_product_name?product_name' => 'wordpress', 'size' => intval(5), 'page' => intval(1) , 'affected' => true
				   
					# Returns versions by product id.
					'by_product_id?product_id' => intval(2075), 'size' => intval(100), 'page' => intval(1), 'affected' => true
					
					);
//$vuln = new VulnDB('versions', $arguments_versions);
//echo $vuln->_json;

/**
 * Classifications examples
 **/
 // General options
 // 'page' => 1
 // 'size' => 20		 
$arguments_classifications = array(

					# submit empty array for list
					'', // empty
					
					# Returns 20 classifications ordered by name.
				   '?size' => intval(5), 'page' => intval(1), 'category' => intval(1),
					);

//$vuln = new VulnDB('classifications', $arguments_classifications);
//echo $vuln->_json;


/**
 * Vulnerabilites examples
 **/
 

 // General options
 //  nested: When set to true the returned list of products/versions is nested within the affected vendors list, defaults to false.
 // 'nested'=>true
 //  additional_info: When set to true additional information from nvd related to the vulnerability is returned with each vulnerability, defaults to false.
 // 'additional_info' => true 
 // 'page' => 1
 // 'size' => 20
$arguments_vulnerabilities = array(
					
					# Returns the 20 most recent vulnerabilities.
				   // submit empty array for list
					'',
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
//$vuln = new VulnDB('vulnerabilities', $arguments_vulnerabilities);
echo $vuln->_json;


?>
