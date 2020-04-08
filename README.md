# SentinelOne

s1.py is a python script that provides an API level integration between SentinelOne and Cognito Detect.
Contextual information is obtained from SentinelOne and applied to a host in the form of tags.  This is triggered manually
by adding a specified tag to a host, or automatically based on the host's Threat and Certainty scoring.
Host enforcement (blocking/unblocking) can be triggered by manually adding a specified tag to a host.

## Prerequisites

Python3, requests, Vectra API Tools (vat), validators, and urllib modules.
A Cognito Detect API key is required and can be generated by going to My Profile and Generating an API token.  

A SentinelOne API key is required which can be obtained from the SentinelOne admin portal.

## Setup

Manually clone or download using git, run setup:
```
git clone https://github.com/vectranetworks/SentinelOne.git
python3 setup.py install
```

Install directly from github utilizing pip3:
```
pip3 install git+https://github.com/vectranetworks/SentinelOne.git
```

## Configuration

A local install will typically install in the following path ***~/.local/lib/<python>/site-packages/s1***. 
Running the script without a valid config in config.py will throw an exception which indicates the full path to the 
script and config.py file.
Edit the config.py file and adjust the required variables according to your environment.

## Running

When ran, the script needs to supplied one or more parameters.  Examples:


```
s1 --tag S1_context
s1 --tag S1_context --tc 75 75
```

The --tag flag will query Detect for active hosts that have the specified tag (S1_context in this example), 
obtain contextual information from SentinelOne, and apply the contextual information as Host Tags back to the host. 

The --tc flag allows a Host's Threat and Certainty scoring thresholds to be supplied for contextual tagging.  Flags can
be combined.

### Typical Usage

```
s1 --tag S1_context --tc 75 75 --blocktag S1_block --unblocktag S1_unblock
```
Specifying multiple flags allows the integration to cover multiple use cases. 

### Recommendations

To test the desired use cases, run the s1.py script from the CLI for testing.  To run in production, the script is
 designed to be called via a cron job.
 
 
## Help Output

usage: s1 [-h] [--tc TC TC] [--tag TAG] [--blocktag BLOCKTAG]
             [--unblocktag UNBLOCKTAG]

Poll Cognito for tagged hosts, extracts SentinelOne contextual information.

optional arguments:
  -h, --help            show this help message and exit  
  --tc TC TC            Poll for hosts with threat and certainty scores >=, eg --tc 50 50  
  --tag TAG             Host Tag for pulling context from SentinelOne  
  --blocktag BLOCKTAG  
  --unblocktag UNBLOCKTAG  
  --verbose             Verbose logging


## Authors

* **Matt Pieklik** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
