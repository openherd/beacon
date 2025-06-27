const { z } = require("zod")
const nodeSchema = z.object({
    macAddress: z.string().optional().nullable(),
    ssid: z.string().optional().nullable(),
    password: z.string().optional().nullable(),
    notes: z.string().optional().nullable(),
    operator: z.string().optional().nullable(),
    location: z.string().optional().nullable(),
    lat: z.string().optional().nullable(),
    lng: z.string().optional().nullable(),
})

module.exports = { nodeSchema }