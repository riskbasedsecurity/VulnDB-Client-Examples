<?php
	/** 
	 * 	// Required the oAuth library. 	// http://oauth.googlecode.com/svn/code/php/OAuth.php
	 * @package VulnDB PHP API Wrapper
	 * @class VulnDB
	 * @desc easy php wrapper for the vulndb run by Cyber Risk Analytics https://cyberriskanalytics.com/
	 * @info Requires API accessible account on VulnDB https://vulndb.cyberriskanalytics.com
	 * @info Full API Information can be found here: https://vulndb.cyberriskanalytics.com/documentation/api 
	 * @version 1
	 * @apiVersion 1
	 * 
	 **/	 
class VulnDB {
	  /**
	   * oAuth Key
	   **/	
	var $oauth_key = '';
	  /**
	   * CoAuth Secret
	   **/	
	var $oauth_secret = '';
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
	  /**
	   * string of cURL header information (debug usage only)
	   **/	
	var $header = "";
	  /**
	   * public json used to return a json string of results
	   **/	
	var $_json = "";
	  /**
	   * public object used to return a object of results
	   **/	
	var $_object = "";
	  /**
	   * preset the current connection state to false to prevent any old looping.
	   **/	
	var $connectState = false;
	  /**
	   * preset the cURL http status code.
	   **/	
	var $cURLhttpCode = 200;
	  /**
	   * preset HTTP method
	   **/	
	var $http_method = "GET";
	  /**
	   * predefined REST Types library for checking correct format before cURL procedure.
	   **/	
	var $endpointType = array(
						'vendors',
						'products',
						'versions',
						'classifications',
						'vulnerabilities'
						);
	  /**
	   * predefined REST Arguments library for checking correct format before cURL procedure.
	   **/	
	var $argumentType = array(
						'by_name',
						'by_name?vendor_name',
						'by_vendor_name?vendor_name',
						'by_vendor_id?vendor_id',
						'by_vendor_id_and_product_name?vendor_name',
						'by_vendor_id_and_product_name?vendor_id',
						'vendor_name',
						'vendor_id',
						'search_query?query',
						'by_product_name?product_name',
						'by_product_id?product_id',
						'product_name',
						'product_id',
						'find_by_bugtraq_id',
						'find_by_certvu_id',
						'find_by_cve_id',
						'find_by_exploitdb_id',
						'find_by_iss_id',
						'find_by_milworm_id',
						'find_by_mssb_id',
						'find_by_nessus_id',
						'find_by_oval_id',
						'find_by_secunia_id',
						'find_by_snort_id',
						'find_by_st_id',
						'osvdb_id',
						'find_next_to_osvdb_id',
						'find_by_classification_id',
						'find_by_classifications_ids?classifications_ids',
						'classifications_ids',
						'find_by_date?start_date',
						'find_by_date?end_date',
						'find_by_date?date_type',
						'find_by_vendor_and_product_name?vendor_name',
						'find_by_vendor_and_product_name?product_name',
						'find_by_vendor_and_product_id?vendor_id',
						'find_by_vendor_and_product_id?product_id',
						'find_by_vendor_id?vendor_id',
						'find_by_product_id?product_id',
						'start_date',
						'end_date',
						'date_type',
						'size', 
						'page',
						'?page',
						'q?classifications_ids', 
						'q?start_date', 
						'q?end_date', 
						'q?date_type', 
						'?size',
						'products_name_cont',
						'find_by_product_id_and_version_id',
						'version_id',
						'find_all_metasploit',
						'find_by_cpe',
						'cpe',
						'find_by_time',
						'hours_ago',
						'affected',
						);

	  /**
	   * preset blank oauthheader
	   **/	
	var $oauth_header = array();
	  /**
	   * pre set blank API end point
	   **/	
	var $api_endpoint	=	'';
	  /**
	   * pre set blank API end point arguments
	   **/	
	var $api_endpoint_args	=	'';
	  /**
	   * Base API path to version 1
	   **/	
	var $apiurl = 'https://vulndb.cyberriskanalytics.com/api/v1/';
	  /**
	   * Authorize path? not needed. but included incase of API updates.
	   **/	
	var $apiauth = 'https://vulndb.cyberriskanalytics.com/oauth/authorize';
	/**
	 * @func __construct
	 * @desc main construct function prepares and sends the endpoint data to the API
	 * @param string $rest_endpoint
	 * @param array $rest_arguments
	 **/
	function __construct($rest_endpoint = '', $rest_arguments = array(), $format = 'json'){
		if(is_array($rest_arguments) && $this->is_endpointType($rest_endpoint)){
			//var_dump($rest_arguments);
			// need to sanatize this string before it goes any further to prevent injection to oauth and site API.
			$this->api_endpoint = $this->apiurl.$rest_endpoint.'/'.$this->glue_endpoint($rest_arguments).'';
			//echo $this->api_endpoint;
			if(!$this->VulnDB_API()){
				$this->_json = 'Failed'; 
			}
			}else{
			$this->_json = 'REST type Does not exsist';
		}
		$this->_object;
	
}
	###########################################################################
	/**
	 * start private functions.
	 **/
	###########################################################################
	/** 
	 * @func glue_endpoint
	 * @desc glue the endpoint arguments together
	 * @param array $arguments
	 * @return array $final_arguments
	 **/
	private function glue_endpoint($arguments){	
		$reverse = false;			
		if(is_array($arguments) && !empty($arguments)){
			$final_arguments_start = '';
				$i=1;
			foreach($arguments as $k => $v){
				if(!$this->is_argumentType($k) && $k != 'by_id') die('Argument '.$k.' is not valid!'); 
				if($k == 'by_id' || $reverse){
					if($reverse){
						$new_arguments[] = $k;
						}else{
						$reverse = true;
						$new_arguments[] = $v.(($i++ < count($arguments)) ? '/' : '');
					}
				}elseif($k == 'osvdb_id'){
					$new_arguments[] = $v;
				}else{	
					$new_arguments[] = $k.'='.$v;
				}
			}
			if(!$reverse){
				$final_arguments = implode('&',$new_arguments);
				}else{
				$final_arguments = implode('',$new_arguments);
			}
		return $final_arguments_start.$final_arguments;
		}
		return '';
	}
	/**
	 * @func OAuthSetup
	 * @desc make the oauth request from the supplied user details.
	 * @return string array $request->to_header()
	 **/
	private function OAuthSetup(){
		if(!class_exists('OAuthConsumer')) require_once('OAuth.php');
		// Establish an OAuth Consumer based on read credentials
		$consumer = new OAuthConsumer( $this->oauth_key, $this->oauth_secret, NULL);
		// Setup OAuth request - Use NULL for OAuthToken parameter
		$request = OAuthRequest::from_consumer_and_token($consumer, NULL, $this->http_method, $this->api_endpoint, NULL);
		// Sign the constructed OAuth request using HMAC-SHA1 - Use NULL for OAuthToken parameter
		$request->sign_request(new OAuthSignatureMethod_HMAC_SHA1(), $consumer, NULL);
		// Extract OAuth header from OAuth request object and keep it handy in a variable
		return $request->to_header();
	}
	
	/**
	 * @func VulnDB_API
	 * @desc make the call to the API via cURL
	 * @return bool
	 **/
	private function VulnDB_API(){
		$ch = curl_init($this->api_endpoint);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);  
		curl_setopt($ch, CURLOPT_FAILONERROR, false);  
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array($this->OAuthSetup()));
		$output = curl_exec($ch);
		$re = curl_getinfo($ch);
		// check for 404 header (we need more checks here to)
		if($re['http_code']=='401' || $re['http_code']=='404' || $re['http_code']=='500' || $re['http_code']=='501' || $re['http_code']=='504'){
			$this->cURLhttpCode = $re['http_code'];
			curl_close($ch);
			$this->error(array('message' => 'cURL failed with http error code: '.$this->cURLhttpCode.' for endpoint: '.$this->api_endpoint, 'func' => 'VulnDB_API'));
			return false;
		}
		if($re['http_code']=='406'){
			if(!$this->nice_not_found_406){
				$this->error(array('message' => 'Entry Not Found', 'func' => 'VulnDB_API'));
				}else{
				$this->not_found_406 = true;
			}
			curl_close($ch);
			return false;
		}
		$this->cURLhttpCode = $re['http_code'];
		// close curl since everything seems fine
		curl_close($ch);
		// set connectState to true since everything seems fine
		$this->connectState = true;
		// populcate the currnetRAWHEADER
		$this->header = $re;
		// Populate the currentHTML
		$this->_json = $output;
		$this->_object = json_decode($output,false);
		return true;
	}
	#####################################################################
	/**
	 * Security and endpoint sanatizing happens below here only.
	 **/
	#####################################################################
	private function is_endpointType($arg){
		if(in_array($arg, $this->endpointType)){
			return true;
		}
	}
	/**
	 * @func is_restType
	 * @desc checks if this is a valid restType
	 * @param string $arg
	 * @return bool
	 **/
	private function is_argumentType($arg){
		if(in_array($arg, $this->argumentType)){
			return true;
		}
	}
	/**
	 * @func  is_gluePiece
	 * @desc check if this is a valid glue piece
	 * @param string $arg
	 * @return bool
	 **/
	 private function is_gluePiece($arg){
		if(in_array($arg, $this->restType)){
			return true;
		}
	 }

	#####################################################################
	 /**
	  * HTML building only
	  **/
	#####################################################################
	private function _wrap_html(){
		return $html;
	}
	#####################################################################
	 /**
	  * Error building only
	  **/
	#####################################################################
	/**
	 * @func error
	 * @desc return pretty errors
	 * @param string $err
	 * @return string $this->error_html
	 **/
	private function error($array){
		if($this->debug){
			echo '<p class="error"><h3>ERROR</h3></p>';
			echo '<p class="error">'.date('y-m-d').'</p>';
			echo '<p class="error">'.$array['message'].'</p>';
			echo '<p class="error">'.$array['func'].'</p>';
		}
	}

// end class
}


?>