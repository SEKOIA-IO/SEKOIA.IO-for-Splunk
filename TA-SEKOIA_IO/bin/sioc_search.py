#!/usr/bin/env python
# coding: utf-8
#

# natives
import sys
import json
import time

# third parties
import splunk
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration
)
from splunklib import client

# internals
from utils import setup_logging

class NoSplunkPatternFoundError(Exception):
    pass


@Configuration()
class SIOCSearchCommand(StreamingCommand):

    def get_session_key(self):
        return self._metadata.searchinfo.session_key

    def get_api_service(self):
        return client.connect(
            token=self.get_session_key(),
            host=splunk.getDefault("host"),
            port=splunk.getDefault("port"),
            app="TA-SEKOIA_IO",
            owner="nobody"
        )
    
    def generate_search_job(self, record):

        try:
            indicator = record
            service = self.get_api_service()
            searchquery = indicator.get("x_pattern_splunk")
            if searchquery is None:
                raise NoSplunkPatternFoundError()

            # inject the index filtering in the query
            searchquery = searchquery.replace(" earliest=", " index="+searched_index+" earliest=")

            # extend the search query to report the result in kvstore
            searchquery += ', index | stats values(index) as match_indexes earliest(_time) as match_first_seen latest(_time) as match_last_seen count as match_count | eval indicator_id="'+str(indicator["id"])+'" |  lookup sioc_lookup indicator_id AS indicator_id OUTPUTNEW | outputlookup sioc_lookup append=True key_field=_key max=1'            
            kwargs_search = {"exec_mode": "normal"}
            
            job = service.jobs.create(
                searchquery, **kwargs_search
            )

            # store job_id in kv store
            self.report_search(job_id=job.name, indicator=indicator)                

        except NoSplunkPatternFoundError:
            raise
        
        except Exception as e:
            self._logger.error(e)
            return "failed"
        return job.name

    def report_search(self, job_id, indicator):
        service = self.get_api_service()
        collection_name = "sioc_search_jobs"
        if collection_name not in service.kvstore:
            service.kvstore.create(collection_name)

        collection = service.kvstore[collection_name]

        kv_fields = {
            "job_id": job_id,
            "status": "triggered",
            "triggered_at": time.time(),
            "match_count": 0,
            "match_first_seen": "",
            "match_last_seen": "",
            "match_indexes": "",
            "indicator_id": indicator['id'],
            "indicator_created": indicator.get('created'),
            "indicator_created_by_ref": indicator.get('created_by_ref'),
            "indicator_indicator_types": indicator.get('indicator_types'),
            "indicator_kill_chain_phases": [
                str(killchain.get('kill_chain_name'))+':'+str(killchain.get('phase_name')) for killchain in indicator.get('kill_chain_phases', [])
            ],
            "indicator_name": indicator.get("name"),
            "indicator_pattern": indicator.get("pattern"),
            "indicator_pattern_type": indicator.get("pattern_type"),
            "indicator_valid_from": indicator.get("valid_from"),
            "indicator_valid_until": indicator.get("valid_until"),
            "indicator_x_pattern_splunk": indicator.get("x_pattern_splunk"),
            "indicator_x_inthreat_sources_refs": indicator.get("x_inthreat_sources_refs")            
        }
        
        res = collection.data.insert(json.dumps(kv_fields))            
        self._logger.info('Search report inserted in collection '+str(collection_name)+': '+str(res))
        
    def stream(self, records):

        self._logger = setup_logging("ta_sekoiaio_siocsearch")

        # max number of search per run
        max_search_per_run = 50
        nb_triggered_search = 0
        for record in records:
            if nb_triggered_search >= max_search_per_run:
                self._logger.warn("Max number of search per run reached, other searches will be processed in next run")
            else:
                try:
                    job_id = self.generate_search_job(record)
                    record["job_id"] = job_id
                    nb_triggered_search += 1
                except NoSplunkPatternFoundError:
                    record["job_id"] = "no pattern"
                
            yield record

if __name__ == "__main__":
    dispatch(SIOCSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
