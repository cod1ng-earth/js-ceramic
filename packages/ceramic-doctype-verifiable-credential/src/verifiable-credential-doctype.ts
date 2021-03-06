import { Doctype, DoctypeConstructor, DoctypeStatic, DocOpts } from "@ceramicnetwork/ceramic-common"
import { Context } from "@ceramicnetwork/ceramic-common"
import { JwtCredentialPayload, transformCredentialInput, validateJwtCredentialPayload } from 'did-jwt-vc'

const DOCTYPE = 'verifiable-credential'

/**
 * content: Verifiable credential content
 * schema: docId of credential schema
 * owners: List of owner Ids
 */
export interface VerifiableCredentialParams {
    content: {
        vcJwt: string
        vcJwtHash?: string
    }
    owners: Array<string>;
}

@DoctypeStatic<DoctypeConstructor<VerifiableCredentialDoctype>>()
export class VerifiableCredentialDoctype extends Doctype {

    /**
     * Change existing Verifiable Credential doctype
     * @param params - Change parameters
     * @param opts - Initialization options
     */
    async change(params: Record<string, any>, opts?: DocOpts): Promise<void> {
        const { content, owners } = params
        const updateRecord = await VerifiableCredentialDoctype._makeRecord(this, this.context, content, owners)
        const updated = await this.context.api.applyRecord(this.id, updateRecord)
        this.state = updated.state
    }

    /**
     * Create Verifiable Credential doctype
     * @param params - Create parameters
     * @param context - Ceramic context
     * @param opts - Initialization options
     */
    static async create(params: Record<string, any>, context: Context, opts?: DocOpts): Promise<VerifiableCredentialDoctype> {
        if (context.user == null) {
            throw new Error('No user authenticated')
        }

        const { content, owners } = params
        const record = await VerifiableCredentialDoctype.makeGenesis({ content, owners }, context, opts)
        return context.api.createDocumentFromGenesis(record, opts)
    }

    /**
     * Creates a genesis record
     * @param params - Create parameters
     * @param context - Ceramic context
     * @param opts - Initialization options
     */
    static async makeGenesis(params: Record<string, any>, context? : Context, opts: DocOpts = {}): Promise<Record<string, any>> {
        if (context.user == null) {
            throw new Error('No user authenticated')
        }

        const { content, owners } = params

        if (!owners) {
            throw new Error('Owner needs to be specified')
        }

        if (!content) {
            throw new Error('Content needs to be specified')
        }

        let jwtContent = await VerifiableCredentialDoctype._getContent(content, context)

        return {
            doctype: DOCTYPE,
            owners,
            content: jwtContent
        }
    }

    /**
     * Make change record
     * @param doctype - Verifiable credential doctype instances
     * @param user - User instance
     * @param newContent - New content
     * @param newOwners - New owners
     */
    static async _makeRecord(doctype: Doctype, context: Context, newContent: any, newOwners?: string[]): Promise<any> {
        if (context.user == null) {
            throw new Error('No user authenticated')
        }

        let owners = newOwners;

        if (!owners) {
            owners = doctype.owners
        }

        if (!newContent) {
            throw new Error('New content needs to be specified')
        }

        let jwtContent = await VerifiableCredentialDoctype._getContent(newContent, context)

        return {
            owners: owners,
            content: jwtContent,
            prev: doctype.head,
            id: doctype.state.log[0]
        }
    }

    static async _getContent(content: any, context: Context): Promise<any> {
        const vcPayload: JwtCredentialPayload = content
        const parsedPayload: JwtCredentialPayload = { iat: undefined, iss: context.user.DID, ...transformCredentialInput(vcPayload) }
        validateJwtCredentialPayload(parsedPayload)

        console.log(parsedPayload)

        const jwt = await context.user.signContent(parsedPayload, { useMgmt: true })
        const cid = await context.ipfs.dag.put(jwt)

        console.log(jwt)

        return {
            vcJwt: jwt,
            vcJwtHash: cid.toString()
        }
    }
}
