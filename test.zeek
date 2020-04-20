@load base/frameworks/sumstats
global allCon: count=0;

event http_reply(c: connection, version: string, code: count, reason: string)
{
	++allCon;
	if (code==404)
	{
		SumStats::observe("404Response", [$host=c$id$orig_h], [$str=reason]);
	}
}

event zeek_init()
{
    local r1 = SumStats::Reducer($stream="404Response", $apply=set(SumStats::UNIQUE,SumStats::SUM));
    SumStats::create([$name="404.detect",
                      $epoch=10mins,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
	                        local res = result["404Response"];
	                        if (res$num>2)
	                        {
	                        	if(res$num/allCon>0.2)
	                        	{
	                        		if (res$unique/res$num >0.5)
	                        		{
	                        			print fmt("%s is a scanner with %d scan attempts on %d URIs",
	                        					key$host, res$num, res$unique);
	                        		}
	                        	}
	                        }
                        }
                       ]
                      );
}