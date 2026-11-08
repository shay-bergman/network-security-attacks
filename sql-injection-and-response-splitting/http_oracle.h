/*
 * http_oracle.h
 *
 * Boolean oracle for blind SQL injection: issue an HTTP request carrying an
 * injected condition and report whether the application's response indicates a
 * true (non-null / non-zero) result.
 */

#ifndef HTTP_ORACLE_H
#define HTTP_ORACLE_H

#include <stdbool.h>

/*
 * Send a request whose order_id condition is "GOOD_ORDER_ID AND (condition)"
 * and return true if the response contains the positive status message.
 * Returns false on any network error or a negative result.
 */
bool sqli_oracle(const char *condition);

#endif /* HTTP_ORACLE_H */
