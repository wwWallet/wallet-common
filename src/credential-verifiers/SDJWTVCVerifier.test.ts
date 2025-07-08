import crypto from "node:crypto";
import nock from 'nock'
import { assert, describe, afterEach, expect, it } from "vitest";
import axios from "axios";
import { Context } from "../interfaces";
import { SDJWTVCVerifier } from "./SDJWTVCVerifier";
import { PublicKeyResolverEngine } from "../PublicKeyResolverEngine";
import { CredentialVerificationError } from "../error";
import { sdJwtFixture } from '../../test/fixtures'

const wrongFormatCredential = `omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQS62BhZBLWnZnN0YXR1c6Frc3RhdHVzX2xpc3SiY2lkeBhsY3VyaXhWaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL3N0YXR1cy84ODc5M2MwMy0xNmFkLTQ0NjgtYmVmNy1jMDgzZDM4YWUyMTlnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNS0wMi0xOFQxNDoxMjowNFppdmFsaWRGcm9twHQyMDI1LTAyLTE4VDE0OjEyOjA0Wmp2YWxpZFVudGlswHQyMDI1LTAzLTA0VDE0OjEyOjA0Wmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xtgBYIKuGxnFMGhNio5-VUJKePlkmw33mloMA9fgqUR0ynOoJAVggWxNyUrVxTPW2riSGxx_U_irluD-vcJIOGGrafGo6JpwCWCDKOCdlxlbeX7mztFkzrM7MsZHs3gEyrmC79X3N2VpxkgNYICmI6iaQPBePM7fzBXqPyX5Gr-wNnWNCNb7wDUz4VDIRBFggfCuu8bFboi9BiRPsM447Ncg9A7K7A28iTEjVy9fmjBIFWCC6z1AlQM8ttJfuIQtPYlurlamh3MvAbSaQoUzAn-9L9gZYIKD1mVbZ5zb-_sp_E6vZCQ_U2QAQVNtbWAznR4xUm6LoB1ggWAn0OSPMM-m8NbgBZ-D6qLV0BEVeSnR4DIsUPUOZDbsIWCDyTDBH9XjK_JIq_W7d19UpmMq1pd1CjrmhfIHsctg3gwlYIK7ejRc3g-pfNGM0WHv4Oh1jfshl03Jvm3cxKHFnIIXmClggjPVDgZmiJEpnM6Zo_mzUQAbW5M6QZuRH43L6BqVeT7wLWCCSVNDu2CjnRkbC7_6m6-G6h8dTDWvlmGz0WD-MUCGERwxYIDpAXdFHgnACMgICXQpJi9nzBDRjsJ8bY1htM9GtgZlKDVggvhyWJk8WGQgokFghnd9DyZKyo8b6VrfAX8WTB0vH1QkOWCBLJFY_nbKL1x-5fbJCqS1IgEn_uMm9NJm2vqorCWwwPg9YIJIg7rTS_E3HAYjcjdV6WSpgZuXa8IKo7f5aC9ibPXQzEFggc_BlS8FdmjVtSqXrA2Xh58naoO0XdTbwclGo9itNTIERWCDzIo5muAIWaawEG69bUPG4mI4pEB5dUhadaUeMUEuwIhJYIEALsAqnwl3T1nC7YtOeDj-7OEHlmcwhCZjY2Qgsr2vCE1ggwG6In0GuGqO1isPXfh2EA7-mi18JAhfumCyQUA5FpYYUWCAL6kBisfFYUIU06t2d0UeqElM-c49VrVqfgYYSIx2JpRVYICYx93c95xCPFdhE03ZlReMnLGSjT_SJgEBMeErv0VlXbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgganiJYJ0goJBbFzWZ52BDtTvTP1Fqb6k80C4UBl6JrFwiWCCWf2o4RIOTRI_UGubc0rCyIDo-o_LYRzYRnWzos3gcSm9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAcBP9-i1suGc_TnH7z4Mp8jFAz2Q__4w7Ju7dDG93XWfCE15E15WYaXUnkYY80tStLInk7nEi6IqEPHJPUyWiyGpuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMZbYGFhRpGZyYW5kb21Q6lwO6tOJcjKhPDMrRPrRFGhkaWdlc3RJRABsZWxlbWVudFZhbHVlGDxxZWxlbWVudElkZW50aWZpZXJsYWdlX2luX3llYXJz2BhYT6RmcmFuZG9tUBwuvU0MGGbT2h94xazpeqloZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhdpGZyYW5kb21Qo6kOsHqedb_9xHVlfCXHf2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZTUxMTQ3cWVsZW1lbnRJZGVudGlmaWVydHJlc2lkZW50X3Bvc3RhbF9jb2Rl2BhYVaRmcmFuZG9tUP6aK3BnaJ4ssYCnhgPSaZpoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWZCRVJMSU5xZWxlbWVudElkZW50aWZpZXJrYmlydGhfcGxhY2XYGFhPpGZyYW5kb21QGR_ZD_ylLFjp_gFyoXxR0WhkaWdlc3RJRARsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFWkZnJhbmRvbVByTlMf_mCOUvaECM5veox_aGRpZ2VzdElEBWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYY6RmcmFuZG9tUED3uH1EYolIFfAdQr8v6pVoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZcB0MTk2NC0wOC0xMlQwMDowMDowMFpxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWE-kZnJhbmRvbVBucDIRMDGt1bMXZVQopw3OaGRpZ2VzdElEB2xlbGVtZW50VmFsdWX0cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzY12BhYVqRmcmFuZG9tUEQqTillqXQcpIwC8F2YOMloZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMoKXZZ4ZDwVRRL4IQ7oDEFoZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTbYGFhXpGZyYW5kb21QdJ-5Oz_55VjO0LOBbnoLs2hkaWdlc3RJRApsZWxlbWVudFZhbHVlYkRFcWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYa6RmcmFuZG9tUMexUIlyfvCgcIUu67OBH6doZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDItMThUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcm1pc3N1YW5jZV9kYXRl2BhYVKRmcmFuZG9tUJ_7jstnoovdbm84Cmh2etFoZGlnZXN0SUQMbGVsZW1lbnRWYWx1ZRkHrHFlbGVtZW50SWRlbnRpZmllcm5hZ2VfYmlydGhfeWVhctgYWFmkZnJhbmRvbVAnc4IFpUS4gxjqo-1DsQNvaGRpZ2VzdElEDWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWE-kZnJhbmRvbVD0dq9e6pNoaa0e_tVlZ-hZaGRpZ2VzdElEDmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzE42BhYU6RmcmFuZG9tUIurbtyPoiia4qsc62iQHIBoZGlnZXN0SUQPbGVsZW1lbnRWYWx1ZWVFUklLQXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYY6RmcmFuZG9tUKgfL0gkbSOApy2APkdkNatoZGlnZXN0SUQQbGVsZW1lbnRWYWx1ZXBIRUlERVNUUkHhup5FIDE3cWVsZW1lbnRJZGVudGlmaWVyb3Jlc2lkZW50X3N0cmVldNgYWFGkZnJhbmRvbVA3gWJEwZz8jgsLsfRJvjMQaGRpZ2VzdElEEWxlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHnYGFhPpGZyYW5kb21QHSMBCaBxBPPy92dCcmoZvWhkaWdlc3RJRBJsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8yMdgYWFakZnJhbmRvbVB4Df01yH0SBmag1gS4xKL9aGRpZ2VzdElEE2xlbGVtZW50VmFsdWVlS8OWTE5xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0edgYWFukZnJhbmRvbVDxOTqapogRuHVS1cLoK7z6aGRpZ2VzdElEFGxlbGVtZW50VmFsdWVmR0FCTEVScWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRo2BhYaaRmcmFuZG9tUOFMkL6pWaVejQQEv7_aS-loZGlnZXN0SUQVbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDMtMDRUMTQ6MTI6MDQuMzc1WnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZQ`;

const exampleCredential = `eyJ0eXAiOiJ2YytzZC1qd3QiLCJ2Y3RtIjpbImV5SjJZM1FpT2lKMWNtNDZaWFV1WlhWeWIzQmhMbVZqTG1WMVpHazZjR2xrT2pFaUxDSnVZVzFsSWpvaVZtVnlhV1pwWVdKc1pTQkpSQ0lzSW1SbGMyTnlhWEIwYVc5dUlqb2lWR2hwY3lCcGN5QmhJRlpsY21sbWFXRmliR1VnU1VRZ1pHOWpkVzFsYm5RZ2FYTnpkV1ZrSUdKNUlIUm9aU0IzWld4c0lHdHViM2R1SUZaSlJDQkpjM04xWlhJaUxDSmthWE53YkdGNUlqcGJleUpzWVc1bklqb2laVzR0VlZNaUxDSnVZVzFsSWpvaVZtVnlhV1pwWVdKc1pTQkpSQ0lzSW5KbGJtUmxjbWx1WnlJNmV5SnphVzF3YkdVaU9uc2liRzluYnlJNmV5SjFjbWtpT2lKb2RIUndPaTh2ZDJGc2JHVjBMV1Z1ZEdWeWNISnBjMlV0YVhOemRXVnlPamd3TURNdmFXMWhaMlZ6TDJ4dloyOHVjRzVuSWl3aWRYSnBJMmx1ZEdWbmNtbDBlU0k2SW5Ob1lUSTFOaTFoWTJSaE16UXdOR015WTJZME5tUmhNVGt5WTJZeU5EVmpZMk0yWWpreFpXUmpaVGc0TmpreE1qSm1ZVFZoTmpZek5qSTROR1l4WVRZd1ptWmpaRGcySWl3aVlXeDBYM1JsZUhRaU9pSldTVVFnVEc5bmJ5SjlMQ0ppWVdOclozSnZkVzVrWDJOdmJHOXlJam9pSXpSall6TmtaQ0lzSW5SbGVIUmZZMjlzYjNJaU9pSWpSa1pHUmtaR0luMHNJbk4yWjE5MFpXMXdiR0YwWlhNaU9sdDdJblZ5YVNJNkltaDBkSEE2THk5M1lXeHNaWFF0Wlc1MFpYSndjbWx6WlMxcGMzTjFaWEk2T0RBd015OXBiV0ZuWlhNdmRHVnRjR3hoZEdVdGNHbGtMbk4yWnlKOVhYMTlYU3dpWTJ4aGFXMXpJanBiZXlKd1lYUm9JanBiSW1kcGRtVnVYMjVoYldVaVhTd2laR2x6Y0d4aGVTSTZXM3NpYkdGdVp5STZJbVZ1TFZWVElpd2liR0ZpWld3aU9pSkhhWFpsYmlCT1lXMWxJaXdpWkdWelkzSnBjSFJwYjI0aU9pSlVhR1VnWjJsMlpXNGdibUZ0WlNCdlppQjBhR1VnVmtsRUlHaHZiR1JsY2lKOVhTd2ljM1puWDJsa0lqb2laMmwyWlc1ZmJtRnRaU0o5TEhzaWNHRjBhQ0k2V3lKbVlXMXBiSGxmYm1GdFpTSmRMQ0prYVhOd2JHRjVJanBiZXlKc1lXNW5Jam9pWlc0dFZWTWlMQ0pzWVdKbGJDSTZJa1poYldsc2VTQk9ZVzFsSWl3aVpHVnpZM0pwY0hScGIyNGlPaUpVYUdVZ1ptRnRhV3g1SUc1aGJXVWdiMllnZEdobElGWkpSQ0JvYjJ4a1pYSWlmVjBzSW5OMloxOXBaQ0k2SW1aaGJXbHNlVjl1WVcxbEluMHNleUp3WVhSb0lqcGJJbUpwY25Sb1gyUmhkR1VpWFN3aVpHbHpjR3hoZVNJNlczc2liR0Z1WnlJNkltVnVMVlZUSWl3aWJHRmlaV3dpT2lKQ2FYSjBhQ0JrWVhSbElpd2laR1Z6WTNKcGNIUnBiMjRpT2lKVWFHVWdZbWx5ZEdnZ1pHRjBaU0J2WmlCMGFHVWdWa2xFSUdodmJHUmxjaUo5WFN3aWMzWm5YMmxrSWpvaVltbHlkR2hmWkdGMFpTSjlMSHNpY0dGMGFDSTZXeUpwYzNOMWFXNW5YMkYxZEdodmNtbDBlU0pkTENKa2FYTndiR0Y1SWpwYmV5SnNZVzVuSWpvaVpXNHRWVk1pTENKc1lXSmxiQ0k2SWtsemMzVnBibWNnWVhWMGFHOXlhWFI1SWl3aVpHVnpZM0pwY0hScGIyNGlPaUpVYUdVZ2FYTnpkV2x1WnlCaGRYUm9iM0pwZEhrZ2IyWWdkR2hsSUZaSlJDQmpjbVZrWlc1MGFXRnNJbjFkTENKemRtZGZhV1FpT2lKcGMzTjFhVzVuWDJGMWRHaHZjbWwwZVNKOUxIc2ljR0YwYUNJNld5SnBjM04xWVc1alpWOWtZWFJsSWwwc0ltUnBjM0JzWVhraU9sdDdJbXhoYm1jaU9pSmxiaTFWVXlJc0lteGhZbVZzSWpvaVNYTnpkV0Z1WTJVZ1pHRjBaU0lzSW1SbGMyTnlhWEIwYVc5dUlqb2lWR2hsSUdSaGRHVWdkR2hoZENCMGFHVWdZM0psWkdWdWRHbGhiQ0IzWVhNZ2FYTnpkV1ZrSW4xZExDSnpkbWRmYVdRaU9pSnBjM04xWVc1alpWOWtZWFJsSW4wc2V5SndZWFJvSWpwYkltVjRjR2x5ZVY5a1lYUmxJbDBzSW1ScGMzQnNZWGtpT2x0N0lteGhibWNpT2lKbGJpMVZVeUlzSW14aFltVnNJam9pU1hOemRXRnVZMlVnWkdGMFpTSXNJbVJsYzJOeWFYQjBhVzl1SWpvaVZHaGxJR1JoZEdVZ2RHaGhkQ0IwYUdVZ1kzSmxaR1Z1ZEdsaGJDQjNhV3hzSUdWNGNHbHlaU0o5WFN3aWMzWm5YMmxrSWpvaVpYaHdhWEo1WDJSaGRHVWlmVjE5Il0sIng1YyI6W1siTUlJQjZEQ0NBWTJnQXdJQkFnSVVaTHNQMU1KeXA0WDUvQ1F6ekwrYXQ0bFJnRjB3Q2dZSUtvWkl6ajBFQXdJd1xuU1RFTk1Bc0dBMVVFQXd3RWRHVnpkREVMTUFrR0ExVUVCaE1DUmxJeERUQUxCZ05WQkFnTUJIUmxjM1F4RFRBTFxuQmdOVkJBY01CSFJsYzNReERUQUxCZ05WQkFvTUJIUmxjM1F3SGhjTk1qVXdOVEk0TURreE1UQXdXaGNOTXpVd1xuTlRJMk1Ea3hNVEF3V2pCSk1RMHdDd1lEVlFRRERBUjBaWE4wTVFzd0NRWURWUVFHRXdKR1VqRU5NQXNHQTFVRVxuQ0F3RWRHVnpkREVOTUFzR0ExVUVCd3dFZEdWemRERU5NQXNHQTFVRUNnd0VkR1Z6ZERCWk1CTUdCeXFHU000OVxuQWdFR0NDcUdTTTQ5QXdFSEEwSUFCQnE2bXExTThJZ25aNkYwTTY2dXNyZjYzV09ROUpwRTFFK0gxTFIvNy8wQlxuWW9uaWVBMjhOOFdYOE52ZTMwK0MzU3pYWjR6TVJtVFBlT1lmMzZCZTRNaWpVekJSTUIwR0ExVWREZ1FXQkJTT1xuSEJYdDlTU2lNRDBOZjF0cHhtcnI0MEo1VWpBZkJnTlZIU01FR0RBV2dCU09IQlh0OVNTaU1EME5mMXRweG1yclxuNDBKNVVqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRRHNhc2ttWUdDTlxud2hpWW02TXRXYUN3QXVxdDhnUnJlM3FDWjBpTHFudUIwd0loQVBNa2VFaHVNLzBoSU0vSkpXK2NnNExPWXB3ZlxuK2Z5Wmw4VHRRWGtZTTNuNCJdXSwiYWxnIjoiRVMyNTYifQ.eyJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwieCI6IkdycWFyVXp3aUNkbm9YUXpycTZ5dF9yZFk1RDBta1RVVDRmVXRIX3ZfUUUiLCJ5IjoiWW9uaWVBMjhOOFdYOE52ZTMwLUMzU3pYWjR6TVJtVFBlT1lmMzZCZTRNZyIsImNydiI6IlAtMjU2In19LCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJqdGkiOiJ1cm46dmlkOjk1NjExYTFlLTczY2YtNGZhNy04YTI3LWYxNGM4MjUxYTU0ZSIsImlhdCI6MTc0MTEwNjk3NSwiZXhwIjoxNzcyNjQyOTc1LCJpc3MiOiJodHRwOi8vd2FsbGV0LWVudGVycHJpc2UtaXNzdWVyOjgwMDMiLCJzdWIiOiJYcXJKNTMtd2pzQlozQVJpc0JydXZkcEZPanZ0UlhsTGczZlFibmZiX21VIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJfc2QiOlsiQjhxTnYxWExxa3JnRFRsSkM2VTZDRTZ3VjFfVExocUh0WXhVUW1FaVVFNCIsIjM3RUpKRzRaRXhOeHM3d20zN2RhRGJOd0Q1M2w0Qlg3ckVKV0hHTUVaR1UiLCJkQUdKb3dSWGdrNlFReG9IR3A4MTdSLUJQUTR0UWprQXlTMG5nd3ZBbEV3IiwiY0MzQ1BJcGVwcEU0TURMLUYya3lXUUpsVlhfbDhzOVZWeE5kbkVHUThWZyIsInhzZGhIRGFQVFBrbTY1cmkxZWhuTnVfbDV3Q24zQk42V2hlcDh0N0N0R1kiLCIzWXVnVVQ5X3B5SDZJZmJveHZEeFlVWkVRN0tFNngybDJIOFNOUEUzdjB3IiwiRjBESzZGTjhiRVZWV05zOTVMbXBSSlZmM2x0TVBXTFZsb09kdkY3UzB6cyIsIk8tUXdJcUVPSERuSFVLNmRrczhCdDcyUUJnV28tWFJJZjdrVHRiQWg5Q28iLCJMNlNBZVN1bXVMbzZHeVBwRkZ6VFh5dTFPZ0dLM0Y0clNkUUVISlhZYzNJIiwiU3pFVFg5cERjUDhlX1FxbEd4QV93ZFY4cXVia2lyNUIwMno3eTdNcEZQTSIsInpxd1ZPeHRpcE0yeVNmbVVXOVhUMFNRNFJ1UHprMFRNejdidE90dUVLcFkiLCJKQW1VUmZWb015eTZDa19iVElqbTZYcUFWeGVFZl9PZGgxQnFrQ3FJX21rIiwiTk9WN3JYcWxLNk5fTHRRXzEzMkF2SXl1cW1FdXo4dGZVNWRULXBvODc3OCIsIm93Z0FaQUd1NXJHNWFCYUtBYkc2MTc4NFhaLW5YOE1SaEhqams0Z1BUWjAiLCJSbjFJZEZmcnV6WXlYQmF2WHlob0ZFWk1FR3hCazZiWGZwTWRlODZVTEU4Iiwid01PSm1NMUF2OFMyMWlDWEJyczB1aFo0UkRIM21WS2RjdUhXX0xwYTFLRSJdfQ.fxtqsiciwyYENEzWR_HK4xXRT1T2Bvt0tYk_vl5ovCthuFI3jA6ig1cIG8hTOEHx9SQRcQ6dLOmOBbYCN0LUpw~WyIxLm1yenI5NGlwZ3giLCJleHBpcnlfZGF0ZSIsIjIwMzUtMDQtMjEiXQ~WyIxLjQwYzA3MGZpdWUiLCJiaXJ0aF9wbGFjZSIsIlVTIl0~WyIxLmtkaW1uMDM0Z2ciLCJiaXJ0aF9kYXRlIiwiMTk5MC0xMC0xNSJd~WyIxLmNpMmoxbzh3dW0iLCJpc3N1YW5jZV9kYXRlIiwiMjAyNS0wMy0wNCJd~WyIxLmo4Mm9oNDVibSIsImRvY3VtZW50X251bWJlciIsIjEyMzEzMjEzIl0~WyIxLmZmc3pkdHgwcHciLCJuYXRpb25hbGl0eSIsWyJVUyJdXQ~WyIxLmc4Z3ExbjVxaXpmIiwiZW1haWxfYWRkcmVzcyIsImpvaG5Ac2FtcGxlLmNvbSJd~WyIxLjA0MDZ2bWgxbSIsImFnZV9vdmVyXzE4IixmYWxzZV0~WyIxLmxvcGhrY3dzbHciLCJtb2JpbGVfcGhvbmVfbnVtYmVyIiwiKzMwODM4ODMzODM4MiJd~WyIxLjE5ZW5hYmUyeGYiLCJyZXNpZGVudF9hZGRyZXNzIiwiMjMsIFJhbmRvbSBzdHIuIDM0NzkzIEFwdCAzIFVTQSJd~WyIxLnd2aGpvaHprdXEiLCJnaXZlbl9uYW1lX2JpcnRoIiwiSm9obiJd~WyIxLmNsN2lmcHc2bG4iLCJnaXZlbl9uYW1lIiwiSm9obiJd~WyIxLjI2Zjh6ZWh5ZDEiLCJmYW1pbHlfbmFtZSIsIkRvZSJd~WyIxLmhiOWh2bTdiY2wiLCJpc3N1aW5nX2F1dGhvcml0eSIsIlBJRDowMDAwMSJd~WyIxLnhrNWV3cGx2b3EiLCJpc3N1aW5nX2NvdW50cnkiLCJHUiJd~WyIxLmw1cnhiOGh2cWgiLCJzZXgiLDFd~`;

const exampleCert = `-----BEGIN CERTIFICATE-----
MIIB6DCCAY2gAwIBAgIUZLsP1MJyp4X5/CQzzL+at4lRgF0wCgYIKoZIzj0EAwIw
STENMAsGA1UEAwwEdGVzdDELMAkGA1UEBhMCRlIxDTALBgNVBAgMBHRlc3QxDTAL
BgNVBAcMBHRlc3QxDTALBgNVBAoMBHRlc3QwHhcNMjUwNTI4MDkxMTAwWhcNMzUw
NTI2MDkxMTAwWjBJMQ0wCwYDVQQDDAR0ZXN0MQswCQYDVQQGEwJGUjENMAsGA1UE
CAwEdGVzdDENMAsGA1UEBwwEdGVzdDENMAsGA1UECgwEdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABBq6mq1M8IgnZ6F0M66usrf63WOQ9JpE1E+H1LR/7/0B
YonieA28N8WX8Nve30+C3SzXZ4zMRmTPeOYf36Be4MijUzBRMB0GA1UdDgQWBBSO
HBXt9SSiMD0Nf1tpxmrr40J5UjAfBgNVHSMEGDAWgBSOHBXt9SSiMD0Nf1tpxmrr
40J5UjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDsaskmYGCN
whiYm6MtWaCwAuqt8gRre3qCZ0iLqnuB0wIhAPMkeEhuM/0hIM/JJW+cg4LOYpwf
+fyZl8TtQXkYM3n4
-----END CERTIFICATE-----`;


/**
 * This certificate was used to sign the issuer's certificate
 */

const invalidRootCert = `-----BEGIN CERTIFICATE-----
MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf/7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2/J0WVeghyw+mIwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr+ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW/U/5S5vAEC5XxcOanusOBroBbU=
-----END CERTIFICATE-----`;




describe("The SDJWTVerifier", () => {
	const vctRegistryUri = 'https://qa.wwwallet.org/public/registry/all.json'

	afterEach(() => {
		nock.cleanAll()
	})

	it("should handle the case where the input is not an SDJWT", async () => {
		const pkResolverEngine = PublicKeyResolverEngine();
		pkResolverEngine.register({ resolve: () => {
			return {
				success: true,
				value: {
					kty: 'EC',
					x: 'VwNK5WDL2D9AdvBP6cLzgFwmmJIYW--uWWdqB3sIIPY',
					y: 'Z7_6W1YQTyJ32RF6oGvDXM_hVYyUFWGQNK5jqw7sgXY',
					crv: 'P-256'
				}
			}
		}});
		const context: Context = {
			clockTolerance: 0,
			lang: 'en-US',
			subtle: crypto.subtle,
			trustedCertificates: [],
			config: {
				vctRegistryUri
			},
		};
		const result = await SDJWTVCVerifier({ context, pkResolverEngine, httpClient: axios })
			.verify({
				rawCredential: wrongFormatCredential, opts: {}
			});

		assert(result.success === false);
		assert(result.error === CredentialVerificationError.InvalidFormat);
	});

	it("should successfully example credential verify credential issued by Wallet Enterprise Issuer", async () => {
		const resolverEngine = PublicKeyResolverEngine();
		resolverEngine.register({ resolve: () => {
			return {
				success: true,
				value: exampleCert
			}
		}});
		const result = await SDJWTVCVerifier({
			context: {
				clockTolerance: 0,
				lang: 'en-US',
				subtle: crypto.subtle,
				trustedCertificates: [
					exampleCert
				],
				config: {
					vctRegistryUri
				},
			},
			pkresolverEngine: resolverEngine
		})
		.verify({
			rawCredential: exampleCredential, opts: {}
		});

		assert(result.success === true);
	});

	it(`should successfully verify vct URL credential`, async () => {
		const { sdJwt, certPem, vctm } = await sdJwtFixture('urn:eudi:pid:1', { vctUrl: 'https://vct.url/vctm' });
		const resolverEngine = PublicKeyResolverEngine();
		resolverEngine.register({ resolve: () => {
			return {
				success: true,
				value: certPem
			}
		}});

		nock('https://vct.url')
			.get('/vctm')
			.reply(200, vctm)

		nock('https://demo-issuer.wwwallet.org')
			.get('/public/creds/pid/person-identification-data-arf-18-schema-example-01.json')
			.reply(200, { type: "object" })

		const result = await SDJWTVCVerifier({
			context: {
				clockTolerance: 0,
				lang: 'en-US',
				subtle: crypto.subtle,
				trustedCertificates: [
					certPem
				],
				config: {
					vctRegistryUri
				},
			},
			pkResolverEngine: resolverEngine,
			httpClient: axios
		})
		.verify({
			rawCredential: sdJwt, opts: { verifySchema: true }
		});

		assert(result.success === true);
	});

	['urn:eu.europa.ec.eudi:pid:1', 'urn:eudi:pid:1'].forEach(vct => {
		it(`should successfully verify ${vct} credential`, async () => {
			const { sdJwt, certPem } = await sdJwtFixture(vct);
			const resolverEngine = PublicKeyResolverEngine();
			resolverEngine.register({ resolve: () => {
				return {
					success: true,
					value: certPem
				}
			}});
			const result = await SDJWTVCVerifier({
				context: {
					clockTolerance: 0,
					lang: 'en-US',
					subtle: crypto.subtle,
					trustedCertificates: [
						certPem
					],
					config: {
						vctRegistryUri
					},
				},
				pkResolverEngine: resolverEngine,
				httpClient: axios
			})
			.verify({
				rawCredential: sdJwt, opts: { verifySchema: true }
			});

			assert(result.success === true);
		});

		it(`should successfully verify ${vct} credential (vctm header)`, async () => {
			const { sdJwt, certPem } = await sdJwtFixture(vct, { vctmInHeader: true });
			const resolverEngine = PublicKeyResolverEngine();
			resolverEngine.register({ resolve: () => {
				return {
					success: true,
					value: certPem
				}
			}});
			const result = await SDJWTVCVerifier({
				context: {
					clockTolerance: 0,
					lang: 'en-US',
					subtle: crypto.subtle,
					trustedCertificates: [
						certPem
					],
					config: {
						vctRegistryUri
					},
				},
				pkResolverEngine: resolverEngine,
				httpClient: axios
			})
			.verify({
				rawCredential: sdJwt, opts: { verifySchema: true }
			});

			assert(result.success === true);
		});
	});

	it.skip("should successfully verify urn:eudi:pda1:1 credential issued by Wallet Enterprise Issuer", async () => {
		const { sdJwt, certPem } = await sdJwtFixture('urn:eudi:pda1:1');
		const resolverEngine = PublicKeyResolverEngine();
		resolverEngine.register({ resolve: () => {
			return {
				success: true,
				value: certPem
			}
		}});
		const result = await SDJWTVCVerifier({
			context: {
				clockTolerance: 0,
				lang: 'en-US',
				subtle: crypto.subtle,
				trustedCertificates: [
					certPem
				],
				config: {
					vctRegistryUri
				},
			},
			pkResolverEngine: resolverEngine,
			httpClient: axios
		})
		.verify({
			rawCredential: sdJwt, opts: { verifySchema: true }
		});

		assert(result.success === true);
	});

	it.skip("should successfully verify urn:eu.europa.ec.eudi:por:1 credential issued by Wallet Enterprise Issuer", async () => {
		const { sdJwt, certPem } = await sdJwtFixture('urn:eu.europa.ec.eudi:por:1');
		const resolverEngine = PublicKeyResolverEngine();
		resolverEngine.register({ resolve: () => {
			return {
				success: true,
				value: certPem
			}
		}});
		const result = await SDJWTVCVerifier({
			context: {
				clockTolerance: 0,
				lang: 'en-US',
				subtle: crypto.subtle,
				trustedCertificates: [
					certPem
				],
				config: {
					vctRegistryUri
				},
			},
			pkResolverEngine: resolverEngine,
			httpClient: axios
		})
		.verify({
			rawCredential: sdJwt, opts: { verifySchema: true }
		});

		assert(result.success === true);
	});

	it("should successfully verify unknown credential issued by Wallet Enterprise Issuer", async () => {
		const { sdJwt, certPem } = await sdJwtFixture('unknown');
		const resolverEngine = PublicKeyResolverEngine();
		resolverEngine.register({ resolve: () => {
			return {
				success: true,
				value: certPem
			}
		}});
		const result = await SDJWTVCVerifier({
			context: {
				clockTolerance: 0,
				lang: 'en-US',
				subtle: crypto.subtle,
				trustedCertificates: [
					certPem
				],
				config: {
					vctRegistryUri
				},
			},
			pkResolverEngine: resolverEngine,
			httpClient: axios
		})
		.verify({
			rawCredential: sdJwt, opts: {}
		});

		assert(result.success === true);
	});

	it.skip("should successfully verify SDJWT+KBJWT issued by Wallet Enterprise Issuer", async () => {
		const result = await SDJWTVCVerifier({ context, pkResolverEngine, httpClient: axios })
		.verify({
			rawCredential: sdJwtCredentialIssuedByWalletEnterpriseWithKbJwt, opts: {
				expectedNonce: "9a0a06d0-0547-4106-b4c6-511937eb047f",
				expectedAudience: "wallet-enterprise-acme-verifier",
			}
		});

		assert(result.success === true);
	});
})
