# Interceptor Proof of Concept
# Created By Casey Smith
# @subTee Twitter
# 8-28-2014
# 2.0.17
# Requires Local Administrator Privileges (Start PowerShell As Administrator)
# Requires Manually changing the Browser Proxy Settings.
# Listens for Incomint Requests on 8081, this is configurable.
# This WILL, install a Rouge CA, and Server Certificates
# For now only use in test 
# Use at your own risk... Educational Purposes Only
#
# TODO - 
<#
	Still Outstanding :
	Auto Proxy Settings Change
	Socket and Request Ansyc
	Add Issuer to Server Certificate Generation
	Certificate Cleantup
	"Powershell Beautify" Parameters, Description, etc... 
	Update Documentation
	Upstream Proxy Authentication
	Binary POST Data handling
	Provide Socket Alternative to HTTPGetWebRequest Usage
	Speed it up..
	
	PowerShell Interceptor
	Author: Casey Smith (@subTee)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
#>

function createCertificate([string] $certSubject, [bool] $isCA)
{
#TODO Add Issued By Property... Aids in Cleanup..

	$CAsubject = $certSubject
	$dn = new-object -com "X509Enrollment.CX500DistinguishedName"
	$dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)

	# Create a new Private Key
	$key = new-object -com "X509Enrollment.CX509PrivateKey"
	$key.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
	# Set CAcert to 1 to be used for Signature
	if($isCA)
		{
			$key.KeySpec = 2 
		}
	else
		{
			$key.KeySpec = 1
		}
	$key.Length = 1024
	$key.MachineContext = 1
	$key.Create() 
	 
	# Create Attributes
	$serverauthoid = new-object -com "X509Enrollment.CObjectId"
	$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
	$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
	$ekuoids.add($serverauthoid)
	$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
	$ekuext.InitializeEncode($ekuoids)

	$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
	$cert.InitializeFromPrivateKey(2, $key, "")
	$cert.Subject = $dn
	$cert.Issuer = $cert.Subject
	$cert.NotBefore = get-date
	$cert.NotAfter = $cert.NotBefore.AddDays(90)
	$cert.X509Extensions.Add($ekuext)
	if ($isCA)
	{
		$basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
		$basicConst.InitializeEncode("true", 1)
		$cert.X509Extensions.Add($basicConst)
	}
	else
	{              
		$signer = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
		$signerCertificate =  new-object -com "X509Enrollment.CSignerCertificate"
		$signerCertificate.Initialize(1,0,4, $signer.Thumbprint)
		$cert.SignerCertificate = $signerCertificate
	}
	$cert.Encode()

	$enrollment = new-object -com "X509Enrollment.CX509Enrollment"
	$enrollment.InitializeFromRequest($cert)
	$certdata = $enrollment.CreateRequest(0)
	$enrollment.InstallResponse(2, $certdata, 0, "")

	if($isCA)
	{              
									
		# Need a Better way to do this...
		$CACertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
		# Install CA Root Certificate
		$StoreScope = "LocalMachine"
		$StoreName = "Root"
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
		$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		$store.Add($CACertificate)
		$store.Close()
									
	}
	else
	{
		return (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $CAsubject })
	} 
     
}

function GetResponse ([System.Net.WebResponse] $response)
{
	#returns a Byte[] from HTTPWebRequest, also for ExceptionHandling
	Try
	{
		#These Are Enums... So Cast them to get Raw values...
		[string]$rawProtocolVersion = [string]("HTTP/" + $response.ProtocolVersion)
		[int]$rawStatusCode = [int]$response.StatusCode
		[string]$rawStatusDescription = [string]$response.StatusDescription
		$rawHeadersString = New-Object System.Text.StringBuilder 
		$rawHeaderCollection = $response.Headers
		$rawHeaders = $response.Headers.AllKeys

		
		foreach($s in $rawHeaders)
		{
			[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) #Use [void] or you will get extra string shit...
		}	
		
		$requestStream = $response.GetResponseStream()
		
		$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		$enc = [System.Text.Encoding]::UTF8
		[byte[]] $rawHeaderBytes = $enc.GetBytes($rstring)
		
		Write-Host $rstring -Fore Yellow
		
		if($response.ContentLength -eq 0)
		{	
			#There is no Response Body to Process..
			$response.Close()
			return $rawHeaderBytes
		}
		
		$contentlen = $response.ContentLength
		[byte[]] $outdata 
		$tempMemStream = New-Object System.IO.MemoryStream
		[byte[]] $respbuffer = New-Object Byte[] 2048
		
		while($true)
			{
				[int] $read = $requestStream.Read($respbuffer, 0, $respbuffer.Length)
				if($read -le 0)
				{
					$outdata = $tempMemStream.ToArray()
					break
				}
				$tempMemStream.Write($respbuffer, 0, $read)
			}
		
		
		[byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
		[System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length )
		[System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length )
		
		$tempMemStream.Close()
		$response.Close()
		
		return $rv
	}
	Catch [System.Net.WebException]
	{
		Write-Host "An Exception Has Occured" 
		#Examine and Return the Response to the Browser.
		#Code duplicates above... So really should write a function here...
		if ($_.Response) 
		{
			return GetResponse $_.Response #A little Recursion is good for the soul
        }

    }#End Catch
	Finally
	{
		$response.Close()
	}

}

function HttpGet([string] $URI, [string] $httpMethod, [string[]] $requestString, [System.Net.WebProxy] $proxy)
{
	Try
	{
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)		
		$request.KeepAlive = $false
		$request.ProtocolVersion = [System.Net.Httpversion]::version10
		$request.ServicePoint.ConnectionLimit = 1
		if($proxy -ne $null) { $request.Proxy = $proxy }
		$request.Method = $httpMethod
		$request.AllowAutoRedirect = $false #Just let the browser follow the redirects..
		$request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
		$request.ReadWriteTimeout = 32000
		
		For ($i = 1; $i -lt $requestString.Length; $i++)
		{
			$line = $requestString[$i] -split ": "
			if ( $line[0] -eq "Host" -Or $line[0] -eq $null ) { continue }
			Try
			{
				#Add Header Properties Defined By Class
				switch($line[0])
				{
					"Accept" { $request.Accept = $line[1] }
					"Connection" { "" }
					"Content-Length" { $request.ContentLength = $line[1] }
					"Content-Type" { $request.ContentType = $line[1] }
					"Expect" { $request.Expect = $line[1] }
					"Date" { $request.Date = $line[1] }
					"If-Modified-Since" { $request.IfModifiedSince = $line[1] }
					"Range" { $request.Range = $line[1] }
					"Referer" { $request.Referer = $line[1] }
					"User-Agent" { $request.UserAgent = $line[1] + " Intercepted Traffic"} #Add Tampering Here...
					"Transfer-Encoding" { $request.TransferEncoding = $line[1]  }
					default {
								if($line[0] -eq "Accept-Encoding")
								{	
									$request.Headers.Add( $line[0], " ") #Take that Gzip... and I'm lazy.. You have to decompress response to tamper
								}
								else
								{
									$request.Headers.Add( $line[0], $line[1])
									#PS - I hate you Cookie Container.  So I'll just go around you.
								}	
								
							}
				}
				
			}
			Catch
			{
				
			}
		}
		
		if ($httpMethod -eq "POST") {
			$postData = $requestString[-1]
			#This Code Assumes... POST is Text Needs to Change...
			#Change this becuase not all POST content is Text...File Uploads etc..
			#Add a Binary Reader here...
			$bytes = [System.Text.Encoding]::UTF8.GetBytes($postData) 
			#$request.ContentType = $encoding
			$request.ContentLength = $bytes.Length
			
			[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
			$outputStream.Write($bytes,0,$bytes.Length)  
			$outputStream.Close()
		}
		
		
		return GetResponse $request.GetResponse()
		
	}
	Catch 
	{
		
    }#End Catch
	Finally    
	{
		
	}

}#Proxied Get

function DoHttpProcessing([System.Net.Sockets.TcpClient] $HTTPclient, [System.Net.WebProxy] $proxy )
{

	Try
	{	
		$enc = [system.Text.Encoding]::UTF8 #Used to Shuttle Bytes and Strings
		$clientStream = $HTTPclient.GetStream()
		$byteArray = new-object System.Byte[] 2048
		[byte[]] $byteClientRequest

		do #Now loop through and process the bytes received...
		 {
		 [int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length) #Read inbound bytes into buffer.
		 $byteClientRequest += $byteArray[0..($NumBytesRead - 1)]  #Emit raw bytes.
		 
		 } While ($clientStream.DataAvailable) 
		
			
		$clientStream.Flush()
		#Now you have a byte[] Get a string...  Caution, not all that is sent is "string" :) Looking at you Google.
		$requestString = $enc.GetString($byteClientRequest)
		
		
		[string[]] $requestArray = ($requestString -split '[\r\n]') |? {$_} 
		[string[]] $methodParse = $requestArray[0] -split " "
		
		#Begin SSL MITM IF Request Contains CONNECT METHOD
		if($methodParse[0] -ceq "CONNECT")
		{
			[string[]] $domainParse = $methodParse[1].Split(":")
			write-host $domainParse[0] -fore Yellow
			
			$connectSpoof = $enc.GetBytes("HTTP/1.1 200 Connection Established`r`nTimeStamp: " + [System.DateTime]::Now.ToString() + "`r`n`r`n")
			
			$clientStream.Write($connectSpoof, 0, $connectSpoof.Length)	
			$clientStream.Flush()
			
			$sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
			
			$sslStream.ReadTimeout = 1
			
			$sslcertfake = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $domainParse[0]  })
			if ($sslcertfake -eq $null)
			{
				$sslcertfake =  createCertificate $domainParse[0] $false
			}
			
			$sslStream.AuthenticateAsServer($sslcertfake, 0, [System.Security.Authentication.SslProtocols]::Ssl3 , 1)
			
			
			$sslbyteArray = new-object System.Byte[] 2048
			[byte[]] $sslbyteClientRequest

			do #Now loop through and process the bytes received...
			 {
			 [int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length) #Read inbound bytes into buffer.
			 $sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]  #Emit raw bytes.
			 } While ($sslStream.DataAvailable) 
			
			$SSLRequest = $enc.GetString($sslbyteClientRequest)
			
			write-host $SSLRequest -fore Cyan
			
			[string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
			[string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
			
			$secureURI = "https://" + $domainParse[0] + $SSLmethodParse[1]
			
			[byte[]] $byteResponse =  HttpGet $secureURI $SSLmethodParse[0] $SSLrequestArray $proxy
			Try
			{
			$sslStream.Write($byteResponse, 0, $byteResponse.Length)
			}
			Catch
			{
				Write-Host "SSL Write Back Error"
			}
			
		}#End CONNECT/SSL Processing
		
		if( ($methodParse[0] -ceq "GET") -Or ($methodParse[0] -ceq "POST") )
		{
			Write-Host $requestString -Fore Magenta
			[byte[]] $proxiedResponse = HttpGet $methodParse[1] $methodParse[0] $requestArray $proxy
			Try
			{
				$clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length)	
			}
			Catch
			{
				Write-Host "Write Back Error"
			}
		}#End Unsecure Proxy
		
			$HTTPclient.Close()		
	}# End HTTPProcessing Block
	Catch
	{
		write-host "DoHTTPProcessing Error"
		write-host $error[0] 
		$HTTPclient.Close()	
	}
	
                
}

function Main()
{

	$CAcertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root"  })
	if ($CACertificate -eq $null)
	{
		createCertificate "__Interceptor_Trusted_Root" $true
	}

	$port = 8081
	$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	$listener.Server.ReceiveTimeout = 60000
	$listener.Server.SendTimeout = 60000
	$listener.Start()
	
	<#
		Define Upstream Proxy here.
		TODO Automate 
		$upstreamProxy = New-Object System.Net.WebProxy("127.0.0.1", 8888)
		OR
		$upstreamProxy = $null #Means Direct Connection
		
	#>
	
	$upstreamProxy = $null # New-Object System.Net.WebProxy("127.0.0.1", 8888) 
	
	while($true){
					$client = New-Object System.Net.Sockets.TcpClient
					$reqString
					Try
					{                 
						#TODO Suboptimal Connections...But works for demonstration
						$client = $listener.AcceptTcpClient()
						DoHttpProcessing $client $upstreamProxy
					
					}
					Catch [System.Exception]
					{
						write-host "Socket Error in Main()"
						write-host $error[0]
						$client.Close()						
					}
					Finally
					{
						
					}

	}


}

Main
