/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.test;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class TestCertificates {

    public static X509Certificate getEndEntityCertificate1() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate1);
    }

    public static PrivateKey getEndEntityCertificate1Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate1PrivateKey, "RSA");
    }

    public static X509Certificate getEndEntityCertificate2() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate2);
    }

    public static PrivateKey getEndEntityCertificate2Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate2PrivateKey, "RSA");
    }

    public static X509Certificate getSubCACertificate1() throws Exception {
        return inflateCertificate(encodedsubCA1Cert);
    }

    public static X509Certificate getEndEntityCertificate1_1() throws Exception {
        return inflateCertificate(encodedEndEntityCertificate1_1);
    }

    public static PrivateKey getEndEntityCertificate1_1Key() throws Exception {
        return inflatePrivateKey(encodedEndEntityCertificate1_1PrivateKey, "RSA");
    }

    public static X509Certificate getEcCErt() throws Exception {
        return inflateCertificate(encodedEcEndEntityCertificate);
    }

    private static X509Certificate inflateCertificate(String encodedCertificate) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate.getBytes())));
        return (X509Certificate) certificate;
    }

    public static PrivateKey getEcCertKey() throws Exception {
        return inflatePrivateKey(encodedEcEndEntityCertificatePrivateKey, "EC");
    }
    private static PrivateKey inflatePrivateKey(String encodedPrivateKey, String keyType) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey.getBytes()));
        KeyFactory kf = KeyFactory.getInstance(keyType);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    // generated with: openssl req -x509 -new -nodes -key ca1.key -out ca1-cert.pem -subj='/CN=SampleCA1' -days 3650
    private static String encodedCA1Cert = "" +
            "MIIDCTCCAfGgAwIBAgIUNy2lHJ6bxmuvv1I3AdnLKzKBYGUwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI2MDcxOTIzMjYzOFoXDTM2MDcx" +
            "NjIzMjYzOFowFDESMBAGA1UEAwwJU2FtcGxlQ0ExMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAt5wDaMa177J2Rp5lo216Jq+1LlmU7bqFwMxOKSy+4Gau" +
            "tt7W6Yx1VHUQEkGdE/UydZ/dsqims717JopVXSemvXgGZFkCNIH4yO4g8lwuTugW" +
            "jI+j+sDuDdIxKEvgadLues6URVsKQlIMFLvVH0vM2IHkYn7BVfHzZ0fBEr2CbIFh" +
            "9GvHoEj/oGUeMabotrc6CJjrCDlkjPSgqlDk0sRC4AaEElGdDF9YE47F8apbsok9" +
            "beZEygyaZ+LArjPW72V3eBne1tqRHcyKkxKNaxP3BY2QLIaIrs8SGsFJfDcwFr7D" +
            "iSOXK9YvNdtACM0A1XsfgIVhmkI/O8sWPnIQ8f8hyQIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQUKhUomEjm9OS9duiVbE+4S750P6QwHwYDVR0jBBgwFoAUKhUomEjm9OS9duiV" +
            "bE+4S750P6QwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEASwpI" +
            "CzQMOybvJSrbIQbywUAHI8aTden+saSO4Cby3gMxZpo+wNGJdzJCk2Qwu1rdzm5w" +
            "5aKlgwTz7JnZ0lLTC3/x918UBSWZT42Sqrt2Y+sXM6/kn5jx09fE+uj90Rv9unEt" +
            "v4Su8GWQB8eb4fCUYxKHJZlQngKN55xG8Te6Nd5sHOD2kw/CpMvjHDX7J/d9waFY" +
            "LQezwLk5NulPbOsr9tY8VDgYRVUUhk6BHgZMfAGH0z96j8tkv1+9IquIy97VVa/r" +
            "CNB/nLJA8WkVMbYUlho5TrDCT0nruXUFG+glDR+UHA9ufeHoKGsM17wWbnQWJkCH" +
            "8K/zXx+ONgZ73qQYQg==";

    // generated with: openssl genrsa -out ca1.key 2048
    private static String encodedCA1PrivateKey = "" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3nANoxrXvsnZG" +
            "nmWjbXomr7UuWZTtuoXAzE4pLL7gZq623tbpjHVUdRASQZ0T9TJ1n92yqKazvXsm" +
            "ilVdJ6a9eAZkWQI0gfjI7iDyXC5O6BaMj6P6wO4N0jEoS+Bp0u56zpRFWwpCUgwU" +
            "u9UfS8zYgeRifsFV8fNnR8ESvYJsgWH0a8egSP+gZR4xpui2tzoImOsIOWSM9KCq" +
            "UOTSxELgBoQSUZ0MX1gTjsXxqluyiT1t5kTKDJpn4sCuM9bvZXd4Gd7W2pEdzIqT" +
            "Eo1rE/cFjZAshoiuzxIawUl8NzAWvsOJI5cr1i8120AIzQDVex+AhWGaQj87yxY+" +
            "chDx/yHJAgMBAAECggEAAwWxpawdqwoiOcPaMvA2okPipNZrJeWb1YJXaASZSLrP" +
            "9ekhmvsJpF//6XkEg6NV1wtQXCQ8CDneeNIumQexzi0XV9gCOgiIppAK4Upkpb5a" +
            "vqoPni1GTdpvnjTvhvZmoAVd+e1HdDODCOVVmvwFrWun7XoeJxLCOak785nEd5I7" +
            "ecJqRO3+YMBzVDlJgVOm5EDX0eC+T9IMEtDazJgHgxUTrVZvtK27SV07u7xQPF+3" +
            "8GwKkiuWF/0RfMwVlV8ohrS2zkKOfTMvunxdyciITTEMaVnvAuxaDHJ5/P0m8dyM" +
            "uARraAyggs7TfVgXmqerIOoBT7lKVMkQhtE+6piWPQKBgQDoTntKRoqFG3yoOtoc" +
            "tvP11RmaXNIFdW15lmle1oACnQI5A7CasVYtv4xGEWN/nddyaSEf1YIka6oMqock" +
            "AFuM3byPF4u7bg4X2pZCh+DhGJWjI1hjrSuJlZu1rdP01+dOkbt17hBe7yrK1H14" +
            "vhGb50trymPhGDyFg4oI6B5BlQKBgQDKVgz10rXr9ItqWo/fQO1HMKc5t26u32/r" +
            "13ddxfaBnVojckXfBzhmDHSfkIdqTgQgD8AaZ2v2h/WrFnbqtmHsiKC0jTViHTi9" +
            "btZJi/iCQ73RxM/YgeEA8bX/Mq2GlrUlc3zpqI4XIQ4BtjgrL0GycrDb8zQzwsIq" +
            "eg4+EIW6ZQKBgQDoQq9Zz7Vm59h2ioDP/Mtlmi4C+5KwCnvt+MhZHbTW6Av03Q+R" +
            "WoSDMOQamgAU88cYiKupnFqF928JQuXixMjDyl5f4na+aoaEqvNYiWn5JA9YEFqr" +
            "LdQ9tur7dlRYlBSbpXD7s42CnTT3ngPk2IPakCIEH1JFF2pLQvybcxftEQKBgQC+" +
            "60lZX1SXa21tkjx1TV9XMDpqhIIk8eI6qFoSmqwKC361OatiUf7Ok+wrcAXGsgzE" +
            "b/g1Mec2fX26zPyyZhuqRBVXqHJ5vNcAMCh0x2VbDS58U/hG8+5qpKi1P41rFKOi" +
            "zgFMvOYuPttnlBgV74ZPKldlg2t7d8ccq4Tq3U5B3QKBgCFgSoKOhTSJVGQTMM2z" +
            "WUSNd8pwuJ7235oFJFyo7qSXntK50WGuyU3iKlKtSaG7G/yUXtS6sdV5KateRDwz" +
            "JGWUNsysbVBi69AjIwbNXU1aAe9rhwe+Rof96q8cU8vF5HSvXRAV6eGFzdWK+8Xb" +
            "kCsHNkIWHTk+qlUa0Uq9MVtV";

    // generated with: openssl req -x509 -new -nodes -key ca2.key -out ca2-cert.pem -subj='/CN=SampleCA2' -days 3650
    private static String encodedCA2Cert = "" +
            "MIIDCTCCAfGgAwIBAgIUWvjeqkYPGTDqZzjMb1RcAzusLwEwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI2MDcxOTIzMjYzOFoXDTM2MDcx" +
            "NjIzMjYzOFowFDESMBAGA1UEAwwJU2FtcGxlQ0EyMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAjdI/cXIyldRRb6z9Q6uW0Ftm7I9oqRzD5cCmIu060gYr" +
            "gDsD+rEcQOEFYMDgZEb0uzpPCjXGQurndu/rgNI4udjHfRERdvD+XOufMx1m7mF2" +
            "h7v64oW648+7uh//mZBmU/364jx9pOlrNF7d01WEPdTkJa4jWLQpbqNHeGglYLbQ" +
            "W6oF4BIPYRk7ldeTfasAiVe7ose7jVbJl+eug7xnAgpfr9ync97tUOcIkOT1pMFZ" +
            "OMnsBc55MMNMfueFg38tVF22LUPsq8yn7QoumlflJmjPL8CzRUbwDCkz5XUUiNpE" +
            "TA04uOq6GftzcP38s7ilQfkLehCmJV4+w50RyCxDSwIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQUOpMYQ7EjuaKKkh/9LxRzcaB2wzAwHwYDVR0jBBgwFoAUOpMYQ7EjuaKKkh/9" +
            "LxRzcaB2wzAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAc56X" +
            "2mVJsD/K1bc4Sja9TiA9X8YMLj0QNVL+pXwBSH2nsUeWnm3Y8Gl5XaT+W6ci3grh" +
            "nim2ieVYjQMSlSWYCh2j74ReMOhCS/IpUNqBurtych+A/BUA+9UQg1mS2jPCwLyO" +
            "Of3Q2f7wyWiJSTy2mV4Pr0Q+58EZrwHTgamTHTDk9nDB8yiuwjcfK9Cq15nICoH8" +
            "q22MEPY5vIMiV4XPaJjNm0wLOE3dnEQ97zstU26cD2xqmhc5iT4T/DrWFvkjX8X2" +
            "Q1gSExw5SkTWgq/JHCOii6lVVd8hPBq0nqLFAESG5yrFVmXcjPnx/Uc5t+rOzaIl" +
            "D98ZHyVl5CpxKTlBQQ==";

    // generated with: openssl genrsa -out ca2.key 2048
    private static String encodedCA2PrivateKey = "" +
            "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCN0j9xcjKV1FFv" +
            "rP1Dq5bQW2bsj2ipHMPlwKYi7TrSBiuAOwP6sRxA4QVgwOBkRvS7Ok8KNcZC6ud2" +
            "7+uA0ji52Md9ERF28P5c658zHWbuYXaHu/rihbrjz7u6H/+ZkGZT/friPH2k6Ws0" +
            "Xt3TVYQ91OQlriNYtCluo0d4aCVgttBbqgXgEg9hGTuV15N9qwCJV7uix7uNVsmX" +
            "566DvGcCCl+v3Kdz3u1Q5wiQ5PWkwVk4yewFznkww0x+54WDfy1UXbYtQ+yrzKft" +
            "Ci6aV+UmaM8vwLNFRvAMKTPldRSI2kRMDTi46roZ+3Nw/fyzuKVB+Qt6EKYlXj7D" +
            "nRHILENLAgMBAAECggEAHxDzPNKbKh78R85JHE22F6YuAZvYfVMDxoxQ2E3HGMKp" +
            "PMmwsXWijsO7/dnCTbUNXwYC0mW9LGNwmKktmWZzbqKB8G+Qt9FKpugmU3gZWBaZ" +
            "dFpFNuG8crLKmJbx0p3DDJsSHgTKMRnAlhRB201cTn8YCvj+XSv593Zk7YdCyNBv" +
            "j23fd/3NUAs3Xg4I7HOMbUa/T3FosK5GD1lOR6xa+jqbgyfEvnBHle8TYVBaVpfe" +
            "8FIAun3R4S35lMPD5TO0q6hE0iM0Cr7Ip0ILoovhhkrgUfya43IYpcyGmzggaFCD" +
            "27DWhPgMPOpdPFZTn0cD/5B2q+tBnDD2Zhx+MqfcoQKBgQDBKQBFTHD+9lr8FAHn" +
            "XBuAAMe3D3EGW9h/vHAzbmxQlP6l7LyXgLJReaNTn9ptIw6apCb6OMKPJZnW0B2T" +
            "ytvZ9kd1mlQ8d1M6Hy5W0FLZsjgfH3NTBCvLd8s3jcwf1ot6yKx214lHu+qS/hAU" +
            "ltbon37OJoSi3wQv7IS0UAjDTQKBgQC79ZRxy9BVAKrbaOpyhjKLbp0PhWqtc9kK" +
            "oXzNKmEWhcTLIpOLvN/k16Uebig2WraRo9ATvqn5CmFC2P3cKaFdyv1ZkUuXtFEj" +
            "g6Dfn/G2mtfoZfOzI0XeCXfxODn5d7rrP4gXcWtpSp42bHI5Cu5gAOiwOwvzKg9C" +
            "SPTEMsUk9wKBgQC/sgEixQoe/j6tjO2WvkJMdnm9owV4Wg4yNsDjSeMU1ckiwh8n" +
            "/AD7+susYihTx0bnEaHdEheEGLzkAwZXditZ1KB2hgKzP3jJZciHP5f5lHU97eh1" +
            "qt4Lv4deSssZjcI+yIjgKGeFWWkjGCC9TjVaB2/BB1j6inmNVh0dFZCcwQKBgCcJ" +
            "QvI7XSI6SEHXUVHFszuoFnCByf0KIVqG3W+SzKUr1QpHPRN5f5p8euuN/0YCowYu" +
            "WmmvYIe7cyW6AUc3Ui8zmFiAx41TQsK4dLHc+wtsr0ix2+IpgjoyBzoO7mN0TVrM" +
            "UAxmXuN4PtGYxkQ4k/dWWP041iuDYbXnhwY0cSNTAn931WcQriCYQfDMMpeVLzHE" +
            "G4bODOjcHxWgOm7e3pr/esQkIcR3Zn1437IZNXWenwE1LhFh8rePk/vohiTVr9rU" +
            "qIEeuXw33E3tfMQTtK0Ks8dG10xOua5DCFUUxIvu6G2RGq294bNNAPRBCwOQ5lZ2" +
            "kFTcmNKZQ14joM6eksSH";

    // generated with:
    // - openssl req -key ee1.key -new -out ee1-cert.csr -subj='/CN=endentity1'
    // - openssl x509 -req -in ee1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out ee1-cert.pem -days 3650 -CAcreateserial
    private static String encodedEndEntityCertificate1 = "" +
            "MIICsDCCAZgCFHSqRHDi5xezQY2sQ97np5tz7vYkMA0GCSqGSIb3DQEBCwUAMBQx" +
            "EjAQBgNVBAMMCVNhbXBsZUNBMTAeFw0yNjA3MTkyMzI2MzlaFw0zNjA3MTYyMzI2" +
            "MzlaMBUxEzARBgNVBAMMCmVuZGVudGl0eTEwggEiMA0GCSqGSIb3DQEBAQUAA4IB" +
            "DwAwggEKAoIBAQCzgx6AiMB31XsQnU5cIbaBFe03yXa9iIqy+BLe1j6vHaWr/gU4" +
            "7I40VeCyjwRptzfPKMl14jcODjnNhNdPcq+nSkNBz7IGETFF+Omic0QvvAscx3Uk" +
            "XfxqwMAWhOj0BOZqSPq8OqywgLlGjy7OVCHJrkLgeU4aEvAxvJL3oD3ZVl9oUvE6" +
            "mMvi2TMGaug3AWvvZo6bueWAsNWSct9//ufHu/rxRCFc3YwHjzQDdQpuXwjsUHMq" +
            "h7m+YZyuuA+OBz4TA3u8g4dnlwkMm3UmPYeefvwQ8sMUeFaBINKgfwAMpysjrhwR" +
            "1tVgoDjjUbDfYFyVITRLkki8rILqJsVkOCCTAgMBAAEwDQYJKoZIhvcNAQELBQAD" +
            "ggEBAIwA5Yoqsv6sxj9uXogdFPZ/Fe2q1nFzVnhCFIAB6xbeJtSaoWDe6S/eJYrS" +
            "9LOWXe9VyyR8g52tabymcV/WGWFiR5p9LUvhTG9SOPan6kWnDfIRJ7WJJsa/R2Zl" +
            "8kdyQrKULxqa8+NnQ43dLWAjTo5BnTpeGMnWb1z/NXg6e/9Sl5rHKZqC+ZCYEwaV" +
            "uOMCSTZNqXUtUI8JaPmMJRgm/cmGeXRS0PuU9HZShqsFvg3fYEUvHfxcBnAQ9GeS" +
            "67hcsz4ewePPfKeup59SudD7Fr+muFQrOh++pdeFIQ6bqIvMJ2l8SdgyKtkOJE2f" +
            "fIgf3G5Sd5iJuGw4qasZ8WkVLfs=";

    // generated with: openssl genrsa -out ee1.key 2048
    private static String encodedEndEntityCertificate1PrivateKey = "" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzgx6AiMB31XsQ" +
            "nU5cIbaBFe03yXa9iIqy+BLe1j6vHaWr/gU47I40VeCyjwRptzfPKMl14jcODjnN" +
            "hNdPcq+nSkNBz7IGETFF+Omic0QvvAscx3UkXfxqwMAWhOj0BOZqSPq8OqywgLlG" +
            "jy7OVCHJrkLgeU4aEvAxvJL3oD3ZVl9oUvE6mMvi2TMGaug3AWvvZo6bueWAsNWS" +
            "ct9//ufHu/rxRCFc3YwHjzQDdQpuXwjsUHMqh7m+YZyuuA+OBz4TA3u8g4dnlwkM" +
            "m3UmPYeefvwQ8sMUeFaBINKgfwAMpysjrhwR1tVgoDjjUbDfYFyVITRLkki8rILq" +
            "JsVkOCCTAgMBAAECggEAWDW6K1cHnNseWg+yjbtTPyNTKfKpkoEiBse4HiARNWPQ" +
            "IS/1yP8U8cqxW4zDkl8h4X4dYPwEKbf7123Lj5K/lej8G76/sBOKruOdiuIxQ3OX" +
            "0lCA05oLizmkKmytPBucTeYGr6/1Y9YdNPru+RyGbeBfpIZ3RoC/3vDXFy96tOzV" +
            "xb6jiVlpzNjfjibirTphRF8xo6sKKDt+z4L6fcFlQT5h91/wcMhFezOOLCa6HQ9w" +
            "OGYslwFRieCdDhYkqOGIDzy2DClMDQPnUfXHo997G6fCBkXuq3gU+7ylSCUcAUae" +
            "K9lqChhHFY9QzHJvjTrGp/VEFPYJaz3xsSSLDNwtwQKBgQDaS3an7hAx48KPL8So" +
            "0XXAYPzVR32ZD29BHAPIWV1vv1uhFbSx3wTYDY6OYA2SCphBaVrsPJoIFhWdXB+e" +
            "ALkMYAEDoMPSXpH0geaNBh65p8p0a5N0+ZTJ8TjMEfaqAhiQcAeKIcAhxtIJKBPl" +
            "FefHWxFvShWc2sEqLYqXKKESiQKBgQDShMVRiNhziRlnNXMUR1RrHPTie9l9aoCD" +
            "rnp1O7aXE+POqrx+ZhaYKHtfp6BGJtctM1n3g6WSyeO18d/eyI7k5xZlV092BsM5" +
            "srLsLrDDIK/HWgNW/0RWIGl+/6X4UM7nH3JgLdIS2dN6VGo/qLOJN61rkvl9GThJ" +
            "5QnZEYdDOwKBgBjf+IlyS04kEguW+eXy2GQvqR/0oY9LfvYAZz3xUQBm4d4dRxXt" +
            "v/OOt+vpbiJyKp9pjf7VeQfq3FOuJ7wtgOi0F+l97FKQjDk8hDUVuXKWeC+EAq2V" +
            "syq/3iUC9wSwcHQlD/bhma8/pLd+ZaX5NQw2iGoSGxxgoRpZTi2jZ5dhAoGADGO1" +
            "/StxmbMa5KEXqbzc8gTdQKsLTL9E2vscx+OAxnlsMdCIkWPOtpvDTwjdfONyTH22" +
            "MMP1raLmHOIkS8c/6abUAZjW21pgiPfEYfQJgSJeVfwtMCSL0AnOS6QeD3QqCR4n" +
            "rBNmRqe9M3jeW+rAzjWRpkAbIMqoLmklYDoQ3NsCgYEAwvl+E2U8LB7qPIpJkEzk" +
            "y6Oy1Ezgc5jhB52kg5RlbLbMJxqViFgpVls2Ve6jPW6P+6cDE4QsYXvOX5H2kq3F" +
            "uIv6hXVmK1fWvYeRYj3EtCHIYGBpszKQgOYuMp36U8flp/SOU7+XgZp1b6Dmo5IP" +
            "m4kHFoCx68R3VNimloDU8W4=";

    // generated with:
    // - openssl req -key ee2.key -new -out ee2-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity2'
    // - openssl x509 -req -in ee2-cert.csr -CAkey ca2.key -CA ca2-cert.pem -out ee2-cert.pem -days 3650
    private static String encodedEndEntityCertificate2 = "" +
            "MIIC3zCCAccCFCcFkibktQJkSO6aC8Kz0s8QfVH5MA0GCSqGSIb3DQEBCwUAMBQx" +
            "EjAQBgNVBAMMCVNhbXBsZUNBMjAeFw0yNjA3MTkyMzI2NDhaFw0zNjA3MTYyMzI2" +
            "NDhaMEQxCzAJBgNVBAYTAk5MMQ0wCwYDVQQKDARLd2lrMREwDwYDVQQLDAhLd2lr" +
            "IERldjETMBEGA1UEAwwKZW5kZW50aXR5MjCCASIwDQYJKoZIhvcNAQEBBQADggEP" +
            "ADCCAQoCggEBAL7zVtMYi8K8Op/gmKQM0nCTIPOyOGKyl/iKYzBoCLuZSWfoHx6D" +
            "mdRSeCLMaIExaoq4KJkTcmDlP6n94sRTcbQ8fUyorrHNwQMSUh6+rcs5TG9aUE+L" +
            "zuU2G6m+Y6D5OAShXUnJpSCmTSHnJ2qVXMMrK96GtLXYFwxTXG54nqEQ+D7whueD" +
            "U9js7M/MI9teKR5MsLIwqaqif8xVGHhGZcrSrcuXNDw7vf/exD3WMbabAaA+5R7w" +
            "d2JyynCPxTeZW5wLWAzBv+uYRWxJvTkaVApNTG6dW0LB6c0gZX+Z7xYt+oybH4N3" +
            "lcn0K6U329FeUY+OGhTBjDRSpsKu2jbLPsUCAwEAATANBgkqhkiG9w0BAQsFAAOC" +
            "AQEAO044SM33pjhkVRSxlt57R/dT004CY0fczSQKTy6sgy/5jIDYpdsYfsyP+9LE" +
            "RXGJzJweyEQV4LwGIB6wC61YK7fIA8s1SS0fuaxv2TQ1Qmi4pcP85qzxiVQBM6gX" +
            "WgCtoMpsbiqbFjpUEA+ALd7CPYPl1SJwUDPcpvWdxNu1e9jIXLubRxlrpEdUYTrI" +
            "H4bprGAA05dr5ERpQ90rmgcXEQLIlVPV6UFe/6NLY+P/Bh6NTiwufjJG25vRdfXo" +
            "Fn/Y3AXHEDSgVtFj/CrxvOLCuWVdBKx/W4OKMYR6BVrrOT1p2jGPxtG0cNpmbhJu" +
            "rV1DQxyU3c5gehBcw5Qm2Sxvrw==";

    // generated with: openssl genrsa -out ee2.key 2048
    private static String encodedEndEntityCertificate2PrivateKey = "" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+81bTGIvCvDqf" +
            "4JikDNJwkyDzsjhispf4imMwaAi7mUln6B8eg5nUUngizGiBMWqKuCiZE3Jg5T+p" +
            "/eLEU3G0PH1MqK6xzcEDElIevq3LOUxvWlBPi87lNhupvmOg+TgEoV1JyaUgpk0h" +
            "5ydqlVzDKyvehrS12BcMU1xueJ6hEPg+8Ibng1PY7OzPzCPbXikeTLCyMKmqon/M" +
            "VRh4RmXK0q3LlzQ8O73/3sQ91jG2mwGgPuUe8Hdicspwj8U3mVucC1gMwb/rmEVs" +
            "Sb05GlQKTUxunVtCwenNIGV/me8WLfqMmx+Dd5XJ9CulN9vRXlGPjhoUwYw0UqbC" +
            "rto2yz7FAgMBAAECggEAA/su13F7khcHYeEps/UdR7Uv/eS8jp8Kn02QI9vUOS6v" +
            "YrgEOuHWvNNU9EsuvDYIWQjd6Wy7LCoB2cyuHbAsfri3V0UGrDTBNKWWvYb10kOv" +
            "kRX6kEedJX14HJUYa3ktIdH7dlf6vJa7C10c0hJ38wz2k5bBzcjJ/wfKtY+7C8Cb" +
            "+ehFWVpfS/QjbR8lJ5iPwbIyygi1Yh18FsoaHVz6RI/3FJyUrPqTZJP0y0M1Cff5" +
            "11R3zZtpVeLJjpd4gkcpj2wPoenajIjxo1A7y9hRKMmDTvP3n/ew6QyhrUATnGPD" +
            "aZv43XG+5kBoC/ZvNXPIpWeumKpIckqkue86VLT1QQKBgQDu68qdxs1iW7FtXF38" +
            "nbV7adeuMeK6H+3P3FWS6cujGozJYjyO//DzQA9SQpsMvwl6ZdL6g6DO8616IS2/" +
            "lR/BgGVQOM7YRND3vBtDS5ykwo6mZTo2kzItcdQVKn3uMJ3X2OY1sR74pMYhqaqi" +
            "eTw962DoIlPv8ulR02uNbnQNEwKBgQDMmbJXIyk7PtZLDjoqxi4yFAQOmSEUe8eb" +
            "86JsxrSvNwyN0i+JqiWNJ/N1uZUEhZ4BECvt0KqvYk61+NuYffcVk7Nlu/0pAKdF" +
            "ZX0uhZnTC5c2IwDJa1fQmhwj6hBzeEQINx6RIBiMqJt4+gmh1XlddfN9bESiSwZL" +
            "FX3au+I3xwKBgQC0tkBA6ne6p6QiFbU5N4hnWn06Up0tLq1PhVZsks3mBlTqlZU8" +
            "jDYRpyhvjdV85JokrBPSS/E713AlaicSO5cTYyw+a1l4l0R/vRXZ5r0KmeYP0Y0g" +
            "bmGLogdKIyOxH7Cj7Hjjr56/btI18AESdySrqPdZXW2jllYIACPfi+XXZQKBgQCQ" +
            "/NG+ojITw+HD6l8Z9LrDzh9Z4PXqOBUp1KrjfqSIDfCdh7ccTTCzKP6EDHEndTCU" +
            "/ErFCjwKcRXqKmIjXBB+f95/V4p9RfNDYDonf5GUVwBe4ssp8SGXt739TV8/FJjR" +
            "YY4Ntbrv4oPaZQXyYv7QVkeoN9MjVxsslhxLpx0V/QKBgCBTitaDLk7GUChiFuty" +
            "tsSbxcFECzXTKPHJ3WqxPMDdBZRzGKHgDwi67wIEnhrK/CzQi5FuryIAvQN4T3Vn" +
            "yPnffLjPVbQJoiAFJet0TJpjlpeFNag16dFsPcdojuiGfLrKPVJSk5dB/DD6XyGW" +
            "4B5rkT/haayG6Z2NKEXp27sA";

    // generated with: openssl genrsa -out subca1.key 2048
    private static String encodedSubCa1PrivateKey = "" +
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpXZ7JVJEUHkhL" +
            "xxto3spfEYwlnHAjXih/hNnVsDbr0YbRDBBPEBVCufeGn/s2vm9Z5aySNmKaWpYw" +
            "1hP7m9kBoMVpq0utsVeQcdCEBPS4DdKeBtjAzYa9N/n+nrH5g8rDrqK6o+uEjfC7" +
            "4aDI+zyyPqCEh0rDhilmK+WxFUQy9cHhSj3cXdexSxjSFPz1eSA+f9U21/+nKBRT" +
            "BAklK/U2MrMUVjbQmIwcsVAkgOuERu7QIfuXZI/lSwkx1fAxbiBD2hMeEU8+nzZU" +
            "3HEzGS5a/WQNkrrX2825L6bfbSWvrb/RHkom1zQrnt22FxUuJ38lzI5vgCH/PpOb" +
            "JYG8p0N1AgMBAAECggEACEwmoxjySaDJLHM6/8qIchtnORF+ufDbPZIZ5Pru2eNI" +
            "PlYft2vjisMXIiCU22P9ixMyPvCMqKC/AnH+hSFnwolomopymPYbAt/clhczERBW" +
            "TPkrZdi73OnQ5N1L/VwsUyVrYgb1WydkD6RYbvhGCzp/vTZunoEkZpXIeUJANtnY" +
            "cneDIzwFrPJcQ2+dRmmFk8zc8KD90J21K1FheOB3ebpFYb8UGbq4E8a4SCHMYz/R" +
            "iOt/mmm9VHjj3u+CFURbhqOS7YzMdkgU/8w6OEaBsSy2utXXEV9xqhGZuQ5q+qqN" +
            "aEuHb/eww6rAUCVehFq0S3eXELV7IzzZmSNP1HGykQKBgQDkN/5nVXSKEu6Hn59i" +
            "r47f9+7d9mFJ1C2pwAzVNGkgMH9gxLBSx2ApNDsarClCimRlMyj59n0CXsXZBwSW" +
            "ajQosPURqdzraeYtS97BjgU4v37jnjFCwfYxDmGZeeiVO8J4N7Odd6X6fVO1W7q6" +
            "QlWzS5ePf8jFyGkpDGcdNGhzsQKBgQC9+5VDUmAC+Mt/acNsn9RJI94bgroCOAlx" +
            "aLk6Vp+umIcKoWqfQy4Tky85ApJXYupjcTyoQX9iImEKyWon51z8avXxhH3m7JRB" +
            "onUQTMbIAY8NwaOI7pFuiog5PJqgl4RW8KD5Ojwmar1BhEPxsl/yY6JyENJDGd83" +
            "aQ65tKJRBQKBgC2g4FVqqX09ocEt8eD6Nreiy3hHXVY0fNi2lBpAe1A7Qgxn5tT2" +
            "FczHK5X+m9U49C+jleq8FGxX5HiqxYkJPNpx3t2kN449ww6FX8kVCwg4iTcbFsBB" +
            "JWbTeEIGNLE5nH0Krfeqx12YlxboeyHoR1gsoeXH561bj2LsnuUg6E1RAoGAWqFJ" +
            "83O4mbJWYdHyiD825i1WJ4mVcrmIx7FNq6bnRkM9KLUYSCGkOXJddLTlWwq1Bftf" +
            "FGUqf4YnBR5QpfiZQ1FDQpQR+7eggi8d6Ui3C3Ky670UZp5ognNTyPpASZv+Zfsk" +
            "z8AYMbt5zWdrgkG1w8wEEqYzqA8PjT9w5uZlCIECgYBTRRbb+FddL+ChyVoKTOnp" +
            "+kC6lnZXumpiBA5Gx2MwKa2XKsAp+ieriiNcjxgs++MK12akWE1jsbFMlXjgpUYC" +
            "pOzsd3u7KJTwZFFdAOJ6pW07zsCKsgpSHMBEopTH2zEpCvctyt1I9G9ykISjTKwY" +
            "QvNtGURTFkyhHX9aVm3atg==";

    // generated with:
    // - openssl req -key subca1.key -new -out subca1-cert.csr -subj='/CN=SubCA'
    // - openssl x509 -req -in subca1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out subca1-cert.pem -days 3650 -CAserial ca1-cert.srl
    // note: -CAserial names the file after the -CA argument's basename plus "-cert.srl" (as -CAcreateserial
    // would have produced for ca1-cert.pem), not "ca1.srl" as the certificate's key-file name might suggest;
    // this cert intentionally lacks a Basic Constraints CA:TRUE extension, matching the previous 512-bit
    // fixture it replaces (see ADVICE doc §5, board finding #3) -- do not "fix" that here.
    private static String encodedsubCA1Cert = "" +
            "MIICqzCCAZMCFHSqRHDi5xezQY2sQ97np5tz7vYlMA0GCSqGSIb3DQEBCwUAMBQx" +
            "EjAQBgNVBAMMCVNhbXBsZUNBMTAeFw0yNjA3MTkyMzI2NDdaFw0zNjA3MTYyMzI2" +
            "NDdaMBAxDjAMBgNVBAMMBVN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" +
            "CgKCAQEAqV2eyVSRFB5IS8cbaN7KXxGMJZxwI14of4TZ1bA269GG0QwQTxAVQrn3" +
            "hp/7Nr5vWeWskjZimlqWMNYT+5vZAaDFaatLrbFXkHHQhAT0uA3SngbYwM2GvTf5" +
            "/p6x+YPKw66iuqPrhI3wu+GgyPs8sj6ghIdKw4YpZivlsRVEMvXB4Uo93F3XsUsY" +
            "0hT89XkgPn/VNtf/pygUUwQJJSv1NjKzFFY20JiMHLFQJIDrhEbu0CH7l2SP5UsJ" +
            "MdXwMW4gQ9oTHhFPPp82VNxxMxkuWv1kDZK619vNuS+m320lr62/0R5KJtc0K57d" +
            "thcVLid/JcyOb4Ah/z6TmyWBvKdDdQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCU" +
            "8IHEbMRRhmsw3f5SCELZTbj0nQshDoSvwwsKmEtAjNVzIMViALFCrA8zy1zhmXT7" +
            "uLItUZK0fMQlGFWEis9J/Vhyip/l9jsBoX+ojaQzrysF2x6HEW3A3we2u5nomUgj" +
            "7Xe6G1A6rQ2P80XcM9mAjY+3OCY+GiIc48AfcxhzyXNNaDXbNnF4MqiaUl2sp6tW" +
            "yGcNPHoRl9omOZT2NIAKXOUjoRi1Tijsl4+mUvMg3gICCRVPaeI7/7Oa2NOwItHl" +
            "nCaAmtMDmZkjiXzZTPgS5DDkba3sqZu61KmWXX6nDet03k3TCjLEt6xawSrJyKYC" +
            "bzvf/YFYnHSyqtrDZ9pX";

    // generated with: openssl genrsa -out ee1_1.key 2048
    private static String encodedEndEntityCertificate1_1PrivateKey = "" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCQ7g7Tn2tFyAel" +
            "q7xavPb7Ox9ENhsZ6WhyYDEN9hSxROM92xG26QYkpVo2cwRJidzT5Glx92RiFtT0" +
            "5vDrsHQ5hDQLiRmras8wQhXVu8WINCKgFsnYaqbe1IMK40qKxObIT/RIyWKEehE4" +
            "EsMAp9AOOEWpJXKvt1UZmmrfKx54iv7SJN+Pt2qvMgI4X3tB91K0Ti7SmIbwgYu1" +
            "asVE88EFbCWgoQuotbvErlJYy071SEcp2W/Rw2rT3++X+jnO2oy5uv6Fwzhk5m4A" +
            "oTrGzblNv2YpE8NT+bJ+BuoBCD9ty7jrSIyayHeSj15lV8NHmdOxcKBLSWagP/Oh" +
            "lPVaOzu1AgMBAAECggEACA9hPjYxvFQDTtyl8ULslmzDkKLUr4R6VVARslXS8Ufk" +
            "PmqqScqcV5nlkj0jyiYzZIphrd+lEspzxfn5AJaT5CX80f5qMc0TIDswpS4X7nr9" +
            "yPrzd0h5Js/ZSNf6q4yHTDEcJBclFjqGriBm/WiXys6o2x8UyX5v6mha1LX8cBYv" +
            "XhQj/W7db0V6cIf4FkoOJHXBikK2olY4PNKz7qUrZZnTLTpcR/X1Th084Ff93VlF" +
            "oPs/9xoPjj4Eto2Gm6KB7mrTandNgeSJRvPpKbZEOznFhdorHaZ6/lB/Jk7otgjK" +
            "RgsuQAz3RqxlLM4AGLCW9LsoyT8aQuifloLSxhFxCQKBgQDM4bMPbzV3k6y9li58" +
            "B9z1LO2ozG8VgUIBJYf2QljPWKq0sLoDo+68v+wHCZUplyE8c3Pn+8T3O0ES2qGF" +
            "IqOOCiDYoHuLibhsByW5RZfX+W7zcymZw0nuWJtq5Gs3zbK+Xufyurg/95TQE5uA" +
            "V/AuoHAgSb7PXB7uCDR9svDMDQKBgQC1Fxes3MF0P4GQ11U2xF/D6s5btFoXH1zc" +
            "Q2+irt/YNk0bhiOTayZlVS2wUtIKyz13h0sAf2f9nDKO8i8PlaSLQUr3ZSaGVZ57" +
            "YbhS6SZuix4EbaBYLks+2UzXFL4cTAFJb/OkKpsXBdD31n2QPMDdo16wICxHOqer" +
            "GwZd/TY8SQKBgQCSYY91r5cb4D7DFdIQe+26nmcO+0FCtB9cglwp7i1Vt5v/jWTZ" +
            "xP6FjPot7QLNvFTaxAJD9PY9TfCob9yHKsCAc2wUWlTq1XMWe+TQApEClgxXlChc" +
            "29KuoFAqhxizvhu/OD+whQevbEy+fcPUZwAL0EVMTGQv8zmGCAa46Ghy4QKBgQCp" +
            "4JLWF3Tm/1glLsuCh+8qU8/nmSVWQZaUDjLgUtor8qyc4FXpSgAH2UL2AIuHkqcD" +
            "xQgn3F0KPQf0rt5U6VUlSUfxEpN0O0djiQUnyg3Cb4DmOIzNjAgMWj7KGWxKEUa3" +
            "xGyzmUBJ9avVgwHhWAy5HjOKV3QSEcUOL1jmvM2u+QKBgBzEUrpc+qlbSjqlki65" +
            "JnBVch5J6yxMdYx49+rYLRayR18vbYHjsl4oLpuL2X3GymJf+cp3B8dCBTh+p+YP" +
            "eokMqL3k7iRzf+YVb/vyzP8EvefjrN1vCpQgdSP68tqv2L56NOqPDoXC6mxHF6EB" +
            "WzKSauAysTkbXfowX/+Cn4gi";

    // generated with:
    // - openssl req -key ee1_1.key -new -out ee1_1-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity1_1'
    // - openssl x509 -req -in ee1_1-cert.csr -CAkey subca1.key -CA subca1-cert.pem -out ee1_1-cert.pem -days 3650
    private static String encodedEndEntityCertificate1_1 = "" +
            "MIIC3TCCAcUCFBpPkAJsIM/PWfSsq/xSdtImJnywMA0GCSqGSIb3DQEBCwUAMBAx" +
            "DjAMBgNVBAMMBVN1YkNBMB4XDTI2MDcxOTIzMjY0OFoXDTM2MDcxNjIzMjY0OFow" +
            "RjELMAkGA1UEBhMCTkwxDTALBgNVBAoMBEt3aWsxETAPBgNVBAsMCEt3aWsgRGV2" +
            "MRUwEwYDVQQDDAxlbmRlbnRpdHkxXzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw" +
            "ggEKAoIBAQCQ7g7Tn2tFyAelq7xavPb7Ox9ENhsZ6WhyYDEN9hSxROM92xG26QYk" +
            "pVo2cwRJidzT5Glx92RiFtT05vDrsHQ5hDQLiRmras8wQhXVu8WINCKgFsnYaqbe" +
            "1IMK40qKxObIT/RIyWKEehE4EsMAp9AOOEWpJXKvt1UZmmrfKx54iv7SJN+Pt2qv" +
            "MgI4X3tB91K0Ti7SmIbwgYu1asVE88EFbCWgoQuotbvErlJYy071SEcp2W/Rw2rT" +
            "3++X+jnO2oy5uv6Fwzhk5m4AoTrGzblNv2YpE8NT+bJ+BuoBCD9ty7jrSIyayHeS" +
            "j15lV8NHmdOxcKBLSWagP/OhlPVaOzu1AgMBAAEwDQYJKoZIhvcNAQELBQADggEB" +
            "ACw47dwagtuHGnfr2QMpyX+QZbkg6noxOxXruXOY19IHQfElSU6RMBd13qico8u0" +
            "KAfs4Po5syuictrUNPz4FVyUc4Qkx+EIECdPEauPeexH3iSZllC/OW/IDP8suXwe" +
            "WdAyYw8rltVMXZs6WS1oSbyKEDADKMnZRAvyJoYvuen++w3guCwuKn6+AL4GD9Ze" +
            "SF/tXG7qsnUbaajoadWhOoJ+lrkWGU3P3Xu1FyVZqabDV5bBBq/DI8WmZnbVA9pd" +
            "0Pz7pXzZgCMD2Lb7zF9jEqRxVn36qFxx9XPXgmN5nQfOcGV3aemGzysBTNUPP63A" +
            "7SHxzfs3UkehYzM3j7tz5CQ=";

    // generated with: openssl req -new -key ec_key.pem -x509 -nodes -days 3650 -out ec1_cert.pem -subj="/CN=SampleECRoot"
    private static String encodedEcEndEntityCertificate = "" +
            "MIIBgzCCASmgAwIBAgIUNzmFH62kWOW8B6eWZSY5j2gyHwkwCgYIKoZIzj0EAwIw" +
            "FzEVMBMGA1UEAwwMU2FtcGxlRUNSb290MB4XDTI0MDUyMTE5NDUyNFoXDTM0MDUx" +
            "OTE5NDUyNFowFzEVMBMGA1UEAwwMU2FtcGxlRUNSb290MFkwEwYHKoZIzj0CAQYI" +
            "KoZIzj0DAQcDQgAEZIPsPYIIdFL8mbd5qPQuIwm7dVa/epFCY4vTnhS2tIw5RKaa" +
            "t1urxRvxMgi1/ColM8F/RFSFErR6A2ANkicNSaNTMFEwHQYDVR0OBBYEFB1vMRJd" +
            "cxjPwYJ9IXziKdyn4FkUMB8GA1UdIwQYMBaAFB1vMRJdcxjPwYJ9IXziKdyn4FkU" +
            "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ01ZZtO6KPhT2Ap" +
            "ppgU3YodziRMezdkcXSawqBnwwVJAiBHY/ZSa3f9R95Jxc8MToS12QggtJaDSFCy" +
            "sV6kzP/1ZA==";

    // generated:
    // - openssl ecparam -out ec_key.pem -name secp256r1 -genkey
    // - openssl pkcs8 -in ec_key.pem -inform PEM -topk8 -nocrypt -out ec_key-pkcs8.der -outform DER
    // - base64 -d -i ec_key-pkcs8.der -o encoded_ec.key
    private static String encodedEcEndEntityCertificatePrivateKey =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/7THqb775dzQvdOy" +
            "43UPGlTbog99/XZb9vTd6kgAZDihRANCAARkg+w9ggh0UvyZt3mo9C4jCbt1Vr96" +
            "kUJji9OeFLa0jDlEppq3W6vFG/EyCLX8KiUzwX9EVIUStHoDYA2SJw1J";

}
