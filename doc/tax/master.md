# Master data

Master data is what events refer to by id and what reports print: the
business itself, the counterparties, the payment accounts. It lives in
`.tax/master/`, one YAML file per kind, each with a `version` key for its
format. `init` writes `business.yaml` from the owner's answers and the
other two files with empty maps. The owner edits all three with an
editor; `tax check` validates them against the rules below, and every
seal fixes them like any other file.

Ids are the keys of the maps in `counterparties.yaml` and
`accounts.yaml`. An id has 1 to 63 characters from `a-z`, `0-9` and `-`,
starts with a letter and does not end with a hyphen. An id is never
reused for something else, since old logs keep referring to it; an entry
that is no longer needed stays in the file.

Amounts are in EUR everywhere the tax law reads them, and the fiscal
year is the calendar year, so neither is a field.

## business.yaml

    version: 1
    name: Max Mustermann IT-Beratung
    owner: Max Mustermann
    kind: freiberuf
    address:
      street: Musterstrasse 1
      postal_code: '10115'
      city: Berlin
      country: DE
    tax_number: 12/345/67890
    vat_id: DE123456789
    profit_method: euer
    vat: kleinunternehmer
    timezone: Europe/Berlin

    field           required  value
    --------------  --------  -------------------------------------------
    version         yes       1
    name            yes       the name the business uses on invoices
    owner           yes       the natural person who is the taxpayer
    kind            yes       freiberuf or gewerbe
    address         yes       street, postal_code, city, country
    tax_number      yes       the Steuernummer as the Finanzamt issued it
    vat_id          no        the USt-IdNr., DE and nine digits
    profit_method   yes       euer
    vat             yes       kleinunternehmer
    timezone        yes       an IANA zone name, such as Europe/Berlin

`postal_code` is a string, quoted so that a leading zero survives.
`country` is an ISO 3166-1 alpha-2 code. `profit_method` and `vat` each
have one allowed value; a further regime adds a value and the code that
handles it, and `tax check` rejects a value it does not know.

## counterparties.yaml

    version: 1
    counterparties:
      telekom:
        name: Telekom Deutschland GmbH
        address:
          street: Landgrabenweg 151
          postal_code: '53227'
          city: Bonn
          country: DE
        vat_id: DE123475223
      acme:
        name: ACME Ltd
        address:
          street: 1 Example Road
          postal_code: EC1A 1BB
          city: London
          country: GB

    field      required  value
    ---------  --------  -----------------------------------------------
    name       yes       the counterparty's name as printed on documents
    address    no        street, postal_code, city, country, as above
    vat_id     no        the counterparty's VAT id in its country's form

An address is required before the counterparty can be the recipient of
an issued invoice, since the recipient's address is a required element
of an invoice; `tax check` reports a customer without one. A supplier
needs only a name.

## accounts.yaml

    version: 1
    accounts:
      giro:
        kind: bank
        name: Geschaeftskonto Sparkasse
        iban: DE02120300000000202051
        currency: EUR
      kasse:
        kind: cash
        name: Bargeld
        currency: EUR
      paypal:
        kind: service
        name: PayPal
        currency: EUR
      usd:
        kind: bank
        name: USD account
        iban: DE89370400440532013000
        currency: USD

    field      required         value
    ---------  ---------------  ----------------------------------------
    kind       yes              bank, cash or service
    name       yes              how the account is shown
    iban       for kind bank    the IBAN without spaces
    currency   yes              an ISO 4217 code

An account is one place money is held or moves through: a bank account,
the cash box, or a payment service such as PayPal or Stripe. Its currency
is the currency the account is kept in; an account in a currency other
than EUR is where the FIFO ledger tracks lots of that currency.
