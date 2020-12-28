from ModSecurity import ModSecurity
from ModSecurity import Rules
from ModSecurity import Transaction
from ModSecurity import ModSecurityIntervention
from ModSecurity import testLogCb
from ModSecurity import LogProperty
import logging

def process_intervention(transaction):
    intervention = ModSecurityIntervention()

    if intervention is None:
        return "None"
    if transaction.intervention(intervention):
        if intervention.log is not None:
            logging.info(intervention.log)

        if not intervention.disruptive:
            logging.debug("Intervention was NOT disruptive")
            return None

        if intervention.url is not None:
            print(intervention.url)
        else:
            print(f"Status resovled: {intervention.status}")
    return None

def cb(data, rule_msg):
    print(data, rule_msg)


logging.basicConfig(level=logging.DEBUG)
modsec = ModSecurity()
modsec.setServerLogCb(
    cb, LogProperty.TextLogProperty)
print(modsec.whoAmI())

rules = Rules()
rule_count = rules.loadFromUri("include.conf")
if rule_count < 1:
    logging.critical(f"Error trying to load rule file: {rules.getParserError()}")

logging.info(f"Loaded {rule_count} rules")

transaction = Transaction(modsec, rules)
transaction.processConnection('127.0.0.1', 33333, '127.0.0.1', 8080)
int_result = process_intervention(transaction)
transaction.processURI('/attack.php?X="><script>alert(1);</script>"&Y=test', 'GET', '1.1')
int_result = process_intervention(transaction)
# Request
transaction.processRequestHeaders()
int_result = process_intervention(transaction)
transaction.processRequestBody()
int_result = process_intervention(transaction)
# Response
transaction.processResponseHeaders(200, 'HTTP 1.2')
int_result = process_intervention(transaction)
transaction.processResponseBody()
int_result = process_intervention(transaction)
transaction.processLogging()
int_result = process_intervention(transaction)
